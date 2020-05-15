
/*
 * send_repeat.js
 *
 * Send Repeat is meant to be used as an include js file. It exposes a function
 * called "send_repeat", which behaves the same as "send", except that it will
 * send the same object repeatedly based on a timer. This is something that
 * would be helpful, for instance, when updating a counter value. Instead of
 * sending a bunch of new values, mark an object to be sent repeatedly and
 * simply update that object's value. This will cause far fewer requests to be
 * made.
 *
 * Requires: dispose.js
 */

var send_repeat_buf = Array();
var send_repeat_ms = 250;

function send_repeat(thing) {
    send_repeat_buf.push(thing);
}

function send_repeat_flush() {
    if ( send_repeat_buf.length > 0 ) {
        send(send_repeat_buf);
    }

    // Schedule next send
    setTimeout(send_repeat_flush, send_repeat_ms);
}

// Be sure we send on dispose
dispose_push(send_repeat_flush);

// Kick off the sender
send_repeat_flush();

/*
 * End send_repeat
 */

