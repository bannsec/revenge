
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

Stalker.follow(THREAD_ID_HERE, {
    events: {
        call: true, // CALL instructions

        // Other events:
        ret: false, // RET instructions
        exec: false, // all instructions: not recommended as it's
                     //                   a lot of data
        block: false, // block executed: coarse execution trace
        compile: false // block compiled: useful for coverage
    },
    onReceive: function (events) {
        parseEvents(events, function (event) {
            event['module'] = Process.getModuleByAddress(event['location']);

            // Ignoring frida-agent libraries
            if (event['module'].name.substring(0, 11) == "frida-agent") {
                return;
            }

            // Optionally only include some
            var include = "INCLUDE_MODULE_HERE"
            if (include != "") {
                if (event['module'].name.toUpperCase() != include.toUpperCase()) {
                    return
                }
            }

            send(event);
    })}
})

