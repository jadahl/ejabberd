%%%----------------------------------------------------------------------
%%% File    : mod_greylist.erl
%%% Author  : Jonas Ådahl <jadahl@gmail.com>
%%% Purpose : Keep track of temporarly, automatically banned hosts
%%% Created : 23 Oct 2010 by Jonas Ådahl <jadahl@gmail.com>
%%%
%%%----------------------------------------------------------------------

%%% @doc Keep track of temporarly, automatically banned hosts.
%%%
%%% Matches the username of failed login attempts to a list of patterns.
%%% Possible use case is when your server is attacked by a botnet where it
%%% would reduce load and network traffic. The side affect is that regular
%%% users could possibly be temporarly banned if their computer or any
%%% computer connecting from the same IP address are under control by the
%%% botnet controller.
%%%
%%% Available options are:
%%%   patterns       - A list of regular expressions
%%%   cleanup_timer  - Timeout interval value (in seconds) for when
%%%                    cleanup of expired greylist entries are to be
%%%                    triggered.
%%%   expire_timeout - Timeout value (in seconds) for how long an IP is to
%%%                    be banned.
%%%
%%% Example:
%%%  - Checks for and removes expired entries every 10 minutes.
%%%  - A banned IP will stay banned for 4 hours.
%%%  - User who failed to login to account ^bad_user_[0-9]{5,}$ (matches
%%%    for example bad_user_3425523 and bad_user_12345 but not
%%%    not_bad_user_153532.
%%%
%%% {modules, [
%%%            {mod_greylist,  [
%%%                             {cleanup_timeout, 600},
%%%                             {expire_timeout, 14400},
%%%                             {patterns, ["^bad_user_[0-9]{5,}$"]}
%%%                            ]
%%%            }
%%%           ]
%%%

-module(mod_greylist).
-author('jadahl@gmail.com').

-behaviour(gen_mod).
-behaviour(gen_server).

-export([
        % gen_mod
        start/2, start_link/2, stop/1,

        % gen_server
        init/1,
        handle_call/3, handle_cast/2, handle_info/2,
        terminate/2, code_change/3,

        % api
        add_greylist/1, is_greylisted/1,

        % hooks
        user_auth_failed/4,
        is_ip_greylisted/2
    ]).

-include("ejabberd.hrl").

-define(PROCNAME, ?MODULE).
-define(DEFAULT_CLEANUP_TIMEOUT_SECS, 60 * 10). % 10 minutes
-define(DEFAULT_GREYLIST_TIMEOUT_SECS, 60 * 60 * 5). % 5 hours

-record(greylist, {
        ipt,     % IP in tuple format
        expires  % expiration time in seconds
    }).

-record(state, {
        match_patterns,
        host,
        cleanup_timer,
        expire_timeout
    }).

start_link(Host, Opts) ->
    gen_server:start_link({local, ?PROCNAME}, ?MODULE, [Host, Opts], []).

start(Host, Opts) ->
    case whereis(?PROCNAME) of
        undefined ->
            mnesia:create_table(greylist,[
                    {disc_copies, [node()]},
                    {attributes, record_info(fields, greylist)}
                ]),
            update_table(),
            ChildSpec = {
                ?PROCNAME,
                {?MODULE, start_link, [Host, Opts]},
                transient,
                1000,
                worker,
                [?MODULE]
            },
            supervisor:start_child(ejabberd_sup, ChildSpec);
        _ ->
            ok
    end.

stop(_Host) ->
    case whereis(?PROCNAME) of
        undefined ->
            ok;
        _ ->
            gen_server:call(?PROCNAME, stop),
            supervisor:terminate_child(ejabberd_sup, ?PROCNAME),
            supervisor:delete_child(ejabberd_sup, ?PROCNAME)
    end.

%
% gen_server
%

init([Host, Opts]) ->
    ejabberd_hooks:add(user_auth_failed, ?MODULE, user_auth_failed, 40),
    ejabberd_hooks:add(check_bl_c2s, ?MODULE, is_ip_greylisted, 75),

    try
        % Required configuration
        CompiledPatterns = case lists:keysearch(patterns, 1, Opts) of
            {value, {patterns, [_ | _] = Patterns}} ->
                [
                    case re:compile(P) of
                        {ok, R} -> R;
                        _ ->
                            throw({error, invalid_regexp, P})
                    end
                    ||
                    P <- Patterns
                ];
            _ ->
                ?ERROR_MSG("Didn't provide any match patterns to mod_greylist.", []),
                throw({error, no_match_patterns})
        end,

        % Optional configuration
        CleanupTimeout = maybe_configured(cleanup_timeout, ?DEFAULT_CLEANUP_TIMEOUT_SECS, Opts),
        ExpireTimeout = maybe_configured(expire_timeout, ?DEFAULT_GREYLIST_TIMEOUT_SECS, Opts),

        {ok, Timer} = timer:send_interval(timer:seconds(CleanupTimeout), cleanup_timer),

        State = #state{
            match_patterns = CompiledPatterns,
            host = Host,
            cleanup_timer = Timer,
            expire_timeout = ExpireTimeout
        },
        {ok, State}
    catch
        {error, invalid_regexp, Pattern2} ->
            ?ERROR_MSG("Failed to compile regular expression ~w", [Pattern2]),
            {stop, {error, invalid_regexp}}
    end.

maybe_configured(Opt, Default, Opts) ->
    case lists:keysearch(Opt, 1, Opts) of
        {value, {_, Configured}} ->
            Configured;
        _ ->
            Default
    end.

handle_call({match, Username}, _From, #state{match_patterns = Patterns} = State) ->
    Res = lists:any(fun(Pattern) ->
                        case re:run(Username, Pattern) of
                            {match, _} -> true;
                            _ -> false
                        end
                    end, Patterns),
    Reply = if Res -> match; true -> no_match end,
    {reply, Reply, State};
handle_call(expire_timeout, _From, #state{expire_timeout = ExpireTimeout} = State) ->
    {reply, {ok, ExpireTimeout}, State};
handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
handle_call(_Req, _From, State) ->
    {reply, {error, badarg}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(cleanup_timer, State) ->
    cleanup_expired(),
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{cleanup_timer = Timer}) ->
    timer:cancel(Timer),
    ejabberd_hooks:delete(user_auth_failed, ?MODULE, user_auth_failed, 40),
    ejabberd_hooks:add(check_bl_c2s, ?MODULE, is_ip_greylisted, 75),
    ok.

code_change(_OldVsn, State, _Extra) ->
    update_table(),
    {ok, State}.

update_table() ->
    Fields = record_info(fields, greylist),
    case mnesia:table_info(greylist, attributes) of
        Fields ->
            ok;
        _ ->
            ?INFO_MSG("Recreating greylist table",[]),
            mnesia:transform_table(greylist, ignore, Fields)
    end.

cleanup_expired() ->
    Now = now_to_seconds(now()),
    F = fun() ->
            mnesia:write_lock_table(greylist),
            mnesia:foldl(
                fun(#greylist{expires = Expires} = R, N) ->
                    if
                        Now >= Expires ->
                            mnesia:delete_object(R),
                            N + 1;
                        true ->
                            N
                    end
                end, 0, greylist)
        end,

    case mnesia:transaction(F) of
        {atomic, Num} ->
            if
                Num > 0 ->
                    ?ERROR_MSG("Cleaned up ~w expired greylist entries.", [Num]);
                true ->
                    ok
            end;
        _Error ->
            ?ERROR_MSG("Couldn't clean up expired entries: ~w", [_Error])
    end.

now_to_seconds({MegaSecs, Secs, _MicroSecs}) ->
    (MegaSecs * 1000000) + Secs.

%
% Hooks
%

user_auth_failed(In, Username, _Host, IP) ->
    case gen_server:call(?PROCNAME, {match, Username}) of
        match ->
            {IPT, _Port} = IP,
            ?INFO_MSG("Abusive user discovered connecting from ~w. Adding ~w to greylist.", [IP, IPT]),
            add_greylist(IPT),
            In;
        no_match ->
            In;
        _Error ->
            ?INFO_MSG("Error: ~w", [_Error]),
            In
    end.

is_ip_greylisted(true, _) -> true;
is_ip_greylisted(_, IPT) ->
    case is_greylisted(IPT) of
        true ->
            true;
        _Res ->
            false
    end.

%
% API
%

add_greylist(IPT) ->
    ExpireTimeout = case gen_server:call(?PROCNAME, expire_timeout) of
        {ok, Value} ->
            Value;
        _Error ->
            ?ERROR_MSG("Couldn't get expire timeout: ~w. Using default.", [_Error]),
            ?DEFAULT_GREYLIST_TIMEOUT_SECS
    end,
    Expires = now_to_seconds(now()) + ExpireTimeout,
    mnesia:dirty_write(#greylist{ipt = IPT, expires = Expires}).

is_greylisted(IPT) ->
    SecsNow = now_to_seconds(now()),
    F = fun() ->
            case mnesia:read(greylist, IPT) of
                [Entry] ->
                    Expires = Entry#greylist.expires,
                    if
                        Expires > SecsNow ->
                            true;
                        true ->
                            mnesia:delete_object(Entry),
                            false
                    end;
                [] ->
                    false
            end
        end,
    case mnesia:transaction(F) of
        {atomic, Res} ->
            Res;
        Error ->
            {error, Error}
    end.

