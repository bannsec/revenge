
// Replace a given function with a loop that waits for a value to be true before going back to the function

var func_ptr = ptr("FUNCTION_HERE");

// Watch this address to know when to continue
var shared_var = ptr(Memory.alloc(Process.pointerSize))

Interceptor.attach(func_ptr, {onEnter: function (args) {

    shared_var.writePointer(ptr(0)); // Init to false

    send("Waiting at function.");

    while ( shared_var.readPointer() == 0 ) {
        Thread.sleep(0.2);
        send("Still waiting at function.");
    };

    send("Done waiting at function.");
},

    onLeave: function (retval) {
        send("Leaving function.");
    },
});

// Let the caller know where the memory is
send(shared_var)
