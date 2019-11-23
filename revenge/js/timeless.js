
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

// obj == object with context
// diff_only == bool, should we only return what changed or return a full
// object (default is false)
function timeless_snapshot(obj, diff_only) {
    var ret = {};
    var resolved;
    ret.is_timeless_snapshot = true;

    var this_call_only_cache = {};

    if ( timeless_snapshot.previous_context === undefined ) {
        timeless_snapshot.previous_context = {};
    }

    //
    // Parse out the context
    // 

    if ( obj.context !== undefined ) {
        ret.context = {};
        var reg, regs;

        if ( timeless_snapshot.regs === undefined ) {
            // Determine what regs to look for
            if ( obj.context.rip ) {
                timeless_snapshot.regs = x64_regs;
            } else if ( obj.context.eip ) {
                timeless_snapshot.regs = x86_regs;
            } else {
                timeless_snapshot.regs = [];
            }
        }

        regs = timeless_snapshot.regs;

        for ( var i = 0; i < regs.length; i++ ) {
            reg = regs[i];

            // Only telescope on things that changed
            if ( timeless_snapshot.previous_context[reg] === undefined || timeless_snapshot.previous_context[reg].thing.compare(obj.context[reg]) !== 0 ) {

                if ( reg == "pc" || reg == "rip" || reg == "eip" ) {
                    var type_hint = "instruction";
                } else {
                    var type_hint = null;
                }

                // If we just resolved this, use the cache
                if ( this_call_only_cache[obj.context[reg]] !== undefined ) {
                    resolved = this_call_only_cache[obj.context[reg]];
                } else {

                    // TODO: When telescoping a fresh object, check if any of the
                    // other regs use this value and update them with the fresh one
                    // we just looked at
                    resolved = telescope(obj.context[reg], 0, type_hint);
                    this_call_only_cache[obj.context[reg]] = resolved;
                }

                ret.context[reg] = resolved;
                timeless_snapshot.previous_context[reg] = ret.context[reg];

            } else {

                // This is an already seen value, only copy if diff_only is NOT
                // true
                if ( diff_only !== true ) {
                    // Copy over the old value
                    ret.context[reg] = timeless_snapshot.previous_context[reg];
                }
            }
        }

        /**********************
         * Invalidating Cache *
         **********************/

        // Frida will hide it's own memory from us, thus if we're executing in
        // Frida this will be undefined.
        
        if ( ret.context.pc.next !== null ) {
            var inst = ret.context.pc.next.thing;
            var operands = inst.operands;
            var base, scale, index, disp;

            for ( var i = 0; i < operands.length; i++ ) {
                var operand = operands[i];

                // Invalidate all mem accesses in cache
                if ( operand.type == "mem" ) {

                    // TODO: Handle mem with segment

                    // [base + index*scale + disp]
                    if ( operand.value.base !== undefined ) {
                        base = timeless_snapshot.previous_context[operand.value.base].thing;
                    } else {
                        base = 0;
                    }

                    if ( operand.value.scale !== undefined ) {
                        scale = operand.value.scale;
                    } else {
                        scale = 1;
                    }

                    if ( operand.value.disp !== undefined ) {
                        disp = operand.value.disp;
                    } else {
                        disp = 0;
                    }

                    if ( operand.value.index !== undefined ) {
                        try {
                            index = timeless_snapshot.previous_context[operand.value.index].thing
                        } catch (e) { 
                            index = operand.value.index;
                        }
                    } else {
                        index = 0;
                    }

                    //var ptr_low = ptr(base + index*scale + disp);
                    var ptr_low = ptr(base).add(index*scale).add(disp);
                    var ptr_high = ptr_low.add(operand.size);
                    timeless_invalidate_cache_context(ptr_low, ptr_high);
                }

                // TODO: Implement {'type': 'imm', 'value': '139708544517310', 'size': 8}
            }

        }

    } else {
        ret.context = null;
    }

    return ret;
}

// Recursively invalidate cache based on what memory was accessed
function timeless_invalidate_cache_context(ptr_low, ptr_high, thing) {
    
    // If we're looking at a specific thing
    if ( thing !== undefined ) {

        // Probably only invalidating ints...
        if ( thing.type !== "int" ) {
            return false;
        }

        var thing_ptr = thing.thing;

        // If we're in the range that just changed
        if ( ptr_low.compare(thing_ptr) <= 0 && ptr_high.compare(thing_ptr) >= 0 ) {
            return true;
        }

        // If the next thing is a string, check if any part of the string is in
        // this area
        if ( thing.next !== null && thing.next.type == "string" ) {
            if ( ptr_low.compare(thing_ptr.add(thing.next.thing.length)) <= 0 && ptr_high.compare(thing_ptr) >= 0 ) {
                return true;
            }
        }

        // If there's more telescoped
        if ( thing.next !== null ) {
            return timeless_invalidate_cache_context(ptr_low, ptr_high, thing.next);
        }

        // Looks like we don't need to invalidate
        return false;
        
    }

    for ( var i = 0; i < timeless_snapshot.regs.length; i++ ) {
        var reg = timeless_snapshot.regs[i];
        var thing = timeless_snapshot.previous_context[reg];

        // If something changed in this context, invalidate it
        if ( timeless_invalidate_cache_context(ptr_low, ptr_high, thing ) ) {
            timeless_snapshot.previous_context[reg] = undefined;
        }
    }
    
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
    obj = timeless_snapshot(obj, true); // using diff_only snapshotting for performance

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
    // Disable telescoping of mem_range for performance
    telescope.mem_range_disabled = true;

    Stalker.queueCapacity = 65536; //1048576; // 32768; //65536;

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
