
////
// Basic stalker
///

//var threads = Process.enumerateThreadsSync()
//for (var i=0; i < threads.length; i++) {


function stalker_follow(tid) {
    var module_map = new ModuleMap();
    var include_from = FROM_MODULES_HERE

    // Unfollow must be called from the source script doing the stalking. Thus, RPC.
    rpc.exports["unfollow"] = function () {
            Stalker.unfollow(tid);
            Stalker.flush();
    }

    // This is automagically called when unloading a script in python
    //rpc.exports["dispose"] = function () { Stalker.unfollow(tid); }
    dispose_push( function () { Stalker.unfollow(tid); } )

    Stalker.follow(tid, {
        events: {
            call: STALK_CALL, // CALL instructions

            // Other events:
            ret: STALK_RET, // RET instructions
            exec: STALK_EXEC, // all instructions: not recommended as it's
                         //                   a lot of data
            block: STALK_BLOCK, // block executed: coarse execution trace
            compile: STALK_COMPILE // block compiled: useful for coverage
        },

        onReceive: function (events) {
            //return send(Stalker.parse(events, {annotate: true, stringify: true}));
            //send(Stalker.parse(events, {annotate: true, stringify: true}));
            
            var filtered_events = [];

            Stalker.parse(events, {annotate: true, stringify: true}).forEach(function x(event) { 
                
                //
                // Module filtering
                //

                var from_module = module_map.findName(ptr(event[1]));

                if ( from_module != null ) {

                    // Ignore frida agent calls
                    if ( from_module.substring(0, 11) == "frida-agent" ) {
                        return;
                    }

                    // Optionally only include from some modules
                    if (include_from.length > 0 && !include_from.includes(from_module)) {
                        return
                    }

                }

                var event_dict = {}

                if ( event[0] == 'call' ) {

                    var to_module   = module_map.findName(ptr(event[2]));
                    event_dict['tid']         = tid;
                    event_dict['type']        = 'call';
                    event_dict['from_ip']     = event[1];
                    event_dict['to_ip']       = event[2];
                    event_dict['depth']       = event[3];
                    event_dict['from_module'] = from_module;
                    event_dict['to_module']   = to_module;

                } else if ( event[0] == 'ret' ) {
                    
                    var to_module   = module_map.findName(ptr(event[2]));
                    event_dict['tid']         = tid;
                    event_dict['type']        = 'ret';
                    event_dict['from_ip']     = event[1];
                    event_dict['to_ip']       = event[2];
                    event_dict['depth']       = event[3];
                    event_dict['from_module'] = from_module;
                    event_dict['to_module']   = to_module;

                } else if ( event[0] == 'exec' ) {
                    
                    event_dict['tid']         = tid;
                    event_dict['type']        = 'exec';
                    event_dict['from_ip']     = event[1];
                    event_dict['from_module'] = from_module;

                } else if ( event[0] == 'block' ) {

                    var to_module   = module_map.findName(ptr(event[2]));
                    event_dict['tid']         = tid;
                    event_dict['type']        = 'block';
                    event_dict['from_ip']     = event[1];
                    event_dict['to_ip']       = event[2];
                    event_dict['from_module'] = from_module;
                    event_dict['to_module']   = to_module;
                    
                } else if ( event[0] == 'compile' ) {

                    var to_module   = module_map.findName(ptr(event[2]));
                    event_dict['tid']         = tid;
                    event_dict['type']        = 'compile';
                    event_dict['from_ip']     = event[1];
                    event_dict['to_ip']       = event[2];
                    event_dict['from_module'] = from_module;
                    event_dict['to_module']   = to_module;

                }

                filtered_events.push(event_dict);
            });

            if ( filtered_events.length != 0 ) {
                send(filtered_events);
            }
        }
    })
}

