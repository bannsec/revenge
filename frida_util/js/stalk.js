
//////
// Borrowed from https://codeshare.frida.re/@mrmacete/stalker-event-parser/
/////


var EV_TYPE_NOTHING = 0;
var EV_TYPE_CALL = 1;
var EV_TYPE_RET = 2;
var EV_TYPE_EXEC = 4;
var EV_TYPE_BLOCK = 8;
var EV_TYPE_COMPILE = 16;

var intSize = Process.pointerSize;
var EV_STRUCT_SIZE = 2 * Process.pointerSize + 2 * intSize;

function parseEvents(blob, callback) {
    var len = getLen(blob);
    for (var i = 0; i !== len; i++) {
        var type = getType(blob, i);
        switch (type) {
            case EV_TYPE_CALL:
                callback(parseCallEvent(blob, i));
                break;
            case EV_TYPE_RET:
                callback(parseRetEvent(blob, i));
                break;
            case EV_TYPE_EXEC:
                callback(parseExecEvent(blob, i));
                break;
            case EV_TYPE_BLOCK:
                callback(parseBlockEvent(blob, i));
                break;
            case EV_TYPE_COMPILE:
                callback(parseCompileEvent(blob, i));
                break;
            default:
                console.log('Unsupported type ' + type);
                break;
        }
    }
}

function getType(blob, idx) {
    return parseInteger(blob, idx, 0);
}

function getLen(blob) {
    return blob.byteLength / EV_STRUCT_SIZE;
}

function parseCallEvent(blob, idx) {
    return {
        type: 'call',
        location: parsePointer(blob, idx, intSize),
        target: parsePointer(blob, idx, intSize + Process.pointerSize),
        depth: parseInteger(blob, idx, intSize + 2 * Process.pointerSize)
    };
}

function parseRetEvent(blob, idx) {
    var ev = parseCallEvent(blob, idx);
    ev.type = 'ret';
    return ev;
}

function parseExecEvent(blob, idx) {
    var loc = parsePointer(blob, idx, intSize);
    return {
        type: 'exec',
        location: loc,
        code: Instruction.parse(loc).toString()
    };
}

function parseBlockEvent(blob, idx) {
    var begin = parsePointer(blob, idx, intSize);
    var end = parsePointer(blob, idx, intSize + Process.pointerSize);
    var i = begin.add(0);
    var code = [];
    while (i.compare(end) < 0) {
        var instr = Instruction.parse(i);
        code.push(i.toString() + '    ' + instr.toString());
        i = instr.next;
    }
    return {
        type: 'block',
        begin: begin,
        end: end,
        code: code.join('\n')
    };
}

function parseCompileEvent(blob, idx) {
    var parsed = parseBlockEvent(blob, idx);
    parsed.type = 'compile';
    return parsed;
}

function parseInteger(blob, idx, offset) {
    return new Int32Array(blob, idx * EV_STRUCT_SIZE + offset, 1)[0];
}

function parsePointer(blob, idx, offset) {
    var view = new Uint8Array(blob, idx * EV_STRUCT_SIZE + offset, Process.pointerSize);
    var stringed = [];
    for (var i = 0; i < Process.pointerSize; i++) {
        var x = view[i];
        var conv = x.toString(16);
        if (conv.length === 1) {
            conv = '0' + conv;
        }
        stringed.push(conv);
    }
    return ptr('0x' + stringed.reverse().join(''));
}

function reverse(arr) {
    var result = [];
    for (var i = arr.length - 1; i >= 0; i--) {
        result.push(arr[i]);
    }
    return result;
}

////
// Basic stalker
///

//var threads = Process.enumerateThreadsSync()
//for (var i=0; i < threads.length; i++) {


function stalker_follow(tid) {
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

                var from_module = module_map.getName(ptr(event[1]));

                // Ignore frida agent calls
                if ( from_module.substring(0, 11) == "frida-agent" ) {
                    return;
                }

                // Optionally only include some
                if (include.length > 0 && !include.includes(from_module)) {
                    return
                }

                var event_dict = {}

                if ( event[0] == 'call' ) {

                    var to_module   = module_map.getName(ptr(event[2]));
                    event_dict['tid']         = tid;
                    event_dict['type']        = 'call';
                    event_dict['from_ip']     = event[1];
                    event_dict['to_ip']       = event[2];
                    event_dict['depth']       = event[3];
                    event_dict['from_module'] = from_module;
                    event_dict['to_module']   = to_module;

                } else if ( event[0] == 'ret' ) {
                    
                    var to_module   = module_map.getName(ptr(event[2]));
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

                    var to_module   = module_map.getName(ptr(event[2]));
                    event_dict['tid']         = tid;
                    event_dict['type']        = 'block';
                    event_dict['from_ip']     = event[1];
                    event_dict['to_ip']       = event[2];
                    event_dict['from_module'] = from_module;
                    event_dict['to_module']   = to_module;
                    
                } else if ( event[0] == 'compile' ) {

                    var to_module   = module_map.getName(ptr(event[2]));
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

            return;

            parseEvents(events, function (event) {
                event['module'] = Process.getModuleByAddress(event['location']);

                // Ignoring frida-agent libraries
                if (event['module'].name.substring(0, 11) == "frida-agent") {
                    return;
                }

                // Optionally only include some
                var include = INCLUDE_MODULE_HERE
                if (include.length > 0 && !include.includes(event['module'].name)) {
                    return
                }

                send(event);
        })}
    })
}

var module_map = new ModuleMap();
var tid = THREAD_ID_HERE;
var include = INCLUDE_MODULE_HERE

stalker_follow(tid);
