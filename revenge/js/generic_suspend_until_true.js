
// Replace a given function with a loop that waits for a value to be true before going back to the function

var func_ptr = ptr("FUNCTION_HERE");

// Watch this address to know when to continue
var shared_var = Memory.alloc(1);
shared_var.writeS8(0); // Init to false

send({"type": "before_replace", "data": func_ptr}, func_ptr.readByteArray(16))

Interceptor.attach(func_ptr, function (args) {

    this.alloc = shared_var;

    var state = {
        "context": this.context,
        "tid": this.threadId,
        "depth": this.depth,
    }

    send({"type": "breakpoint_hit", "data": state});

    while ( shared_var.readS8() == 0 ) {

        Thread.sleep(0.2);
        //send("Still waiting for variable change at " + shared_var);
    }

    send({"type": "breakpoint_leave", "data": state});
});

// Let the caller know where the memory is
send({"type": "resume_pointer", "data": shared_var});
