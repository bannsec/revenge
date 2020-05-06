
/*
 * Handle uncaught exceptions by sending the exception information off and pausing execution
 *
 * Requires: dispose.js, send_batch.js, telescope.js, timeless.js
 */

Process.setExceptionHandler(
    function (details) { 

        // Give us a way to cleanly exit
        var wait_for = Memory.alloc(1);
        wait_for.writeS8(0);

        details.thread_id = Process.getCurrentThreadId();
        details.wait_for = wait_for;

        details.context = timeless_snapshot(details, false).context;
        send(details);

        while ( wait_for.readS8() == 0 ) { Thread.sleep(0.25); };

        // frida should clean up this memory alloc once it loses this reference
        return false;
    }
);
