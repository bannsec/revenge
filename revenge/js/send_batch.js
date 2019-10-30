
/*
 * send_batch.js
 *
 * Send Batch is meant to be used as an include js file. It exposes a function
 * called "send_batch", which behaves the same as "send", except that it will
 * send based on a timer, rather than immediately. This is most beneficial for
 * things that will be sending a lot of data, as it will batch them together to
 * be more efficient (calls to python are SLOW).
 *
 * Requires: dispose.js
 */

var send_batch_buf = Array();
var send_batch_ms = 250;

function send_batch(thing) {
    send_batch_buf.push(thing);
}

function send_batch_flush() {
    // Actually sends the buf
    if ( send_batch_buf.length > 0 ) {
        send(send_batch_buf);
        send_batch_buf = Array();
    }

    // Schedule next send
    setTimeout(send_batch_flush, send_batch_ms);
}

// Be sure we send on dispose
dispose_push(send_batch_flush);

// Kick off the sender
send_batch_flush();

/*
 * End send_batch
 */

