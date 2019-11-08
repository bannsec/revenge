
/*
 * This is just created for testing purposes. It's not likely what you're
 * looking for.
 */

function add_echo () {
    rpc.exports.echo = echo;
}

function echo(x) {
    send(x);
}
