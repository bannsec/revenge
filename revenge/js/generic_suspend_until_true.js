
// Replace a given function with a loop that waits for a value to be true before going back to the function

var func_ptr = ptr("FUNCTION_HERE");

// Watch this address to know when to continue
const shared_var = Memory.alloc(1)
shared_var.writeS8(0); // Init to false

Interceptor.attach(func_ptr, function (args) {

    this.alloc = shared_var;

    send("Waiting at function.");

    while ( shared_var.readS8() == 0 ) {

        Thread.sleep(0.2);
        send("Still waiting for variable change at " + shared_var);
    };

    send("Done waiting at function.");
});

// Let the caller know where the memory is
send(shared_var)
