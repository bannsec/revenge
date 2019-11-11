
/*
 * timeless.js
 *
 * This library implements both the tracing as well as snapshot creation for
 * timeless tracing ability.
 *
 * Requires: dispose.js, send_batch.js, telescope.js
 */

/* timeless_snapshot takes in an object and returns a timeless_snapshot
 * dictionary object with information.
 *
 * The object should have at least one of the following optional fields
 *   - context (frida context object)
 *   - returnAddress (ptr to the current return address)
 *   - errno (unix error)
 *   - lastError (windows error)
 *   - threadId (current thread)
 *   - detph (current call depth)
 */

// NOTE: Make sure to start the regs arrays with pc. This is for type hinting
// and cache stuff!
var x64_regs = ['pc', 'sp', 'rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip'];
var x86_regs = ['pc', 'sp', 'eip', 'esp', 'ebp', 'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi'];
var timeless_module_map = new ModuleMap();

function timeless_snapshot(obj) {
    var ret = {};
    ret.is_timeless_snapshot = true;

    // Only look up each value once.
    var cache = {};
    
    //
    // Parse out the context
    // 

    if ( obj.context !== undefined ) {
        ret.context = {};
        var reg, regs;

        if ( obj.context.rip ) {
            regs = x64_regs;
        } else if ( obj.context.eip ) {
            regs = x86_regs;
        } else {
            regs = [];
        }

        for ( var i = 0; i < regs.length; i++ ) {
            reg = regs[i];

            // Check the cache
            if ( cache[obj.context[reg]] !== undefined ) {
                ret.context[reg] = cache[obj.context[reg]];
                continue;
            }

            if ( reg === "pc" ) {
                var type_hint = "instruction";
            } else {
                var type_hint = null;
            }

            ret.context[reg] = telescope(obj.context[reg], 0, type_hint);
            cache[obj.context[reg]] = ret.context[reg];
        }

    } else {
        ret.context = null;
    }

    return ret;
}

// This gets called with every instruction that's executed
function timeless_parse_instruction(context) {

    var depth = timeless_parse_instruction.depth;
    
    if ( depth === undefined ) {
        depth = 1;
        timeless_parse_instruction.depth = 1;
    }

    //
    // Module filtering
    //

    var from_module = timeless_module_map.findName(context.pc);

    if ( from_module != null ) {

        // Ignore frida agent calls
        if ( from_module.substring(0, 11) == "frida-agent" ) {
            return;
        }

        // Optionally only include from some modules
        //if (include_from.length > 0 && !include_from.includes(from_module)) {
        //    return;
        //}

    }

    var obj = {};
    obj.context = context;
    obj = timeless_snapshot(obj);

    // TODO: Validate this... Currently, the only time this should happen is
    // when we end up stalking into Frida's own memory, which it tries to hide
    // from us. This should be OK to ignore. Theoretically..
    if ( obj.context.pc.next === null ) {
        return;
    }

    var pc_groups = obj.context.pc.next.thing.groups || [];

    if ( pc_groups.includes("call") ) {
        timeless_parse_instruction.depth += 1;
    } else if ( pc_groups.includes("ret") ) {
        timeless_parse_instruction.depth -= 1;
    }

    obj.depth = depth;
    send_batch(obj);
}

function timeless_transformer(iterator) {
    var instruction = null;

    while ((instruction = iterator.next()) !== null ) {
        iterator.putCallout(timeless_parse_instruction);
        iterator.keep();
    }
}

function timeless_trace(tid) {
    Stalker.queueCapacity = 1048576; // 32768; //65536;

    // This is automagically called when unloading a script in python
    dispose_push( function () { Stalker.unfollow(tid); Stalker.flush(); } );

    // Unfollow must be called from the source script doing the stalking. Thus, RPC.
    rpc.exports.unfollow = function () {
            Stalker.unfollow(tid);
            Stalker.flush();
    };
    
    Stalker.follow(tid, {
        events: {call: true, ret: true, exec: true},
        transform: timeless_transformer,
    });
}
