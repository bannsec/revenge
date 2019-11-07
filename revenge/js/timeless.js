
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

var x64_regs = ['pc', 'sp', 'rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip'];
var x86_regs = ['pc', 'sp', 'eip', 'esp', 'ebp', 'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi'];

function timeless_snapshot(obj) {
    var ret = Object();
    ret["is_timeless_snapshot"] = true;
    
    //
    // Parse out the context
    // 

    if ( obj.context !== undefined ) {
        ret["context"] = Object();
        var reg, regs;

        if ( obj.context["rip"] ) {
            regs = x64_regs;
        } else if ( obj.context["eip"] ) {
            regs = x86_regs;
        } else {
            regs = [];
        }

        for ( var i = 0; i < regs.length; i++ ) {
            reg = regs[i];
            ret["context"][reg] = telescope(obj.context[reg]);
        }

    } else {
        ret["context"] = null;
    }

    return ret;
}
