
/*
 * dispose.js
 *
 * Library to handle adding multiple dispose events
 */

var dispose_array = Array();

function dispose_push(func) {
    dispose_array.push(func);
}

if ( typeof(rpc.exports.dispose) == "function" ) {
    dispose_array.push(rpc.exports.dispose);
}

rpc.exports.dispose = function () {
    for (var i=0; i < dispose_array.length; i++)  dispose_array[i]();
};

/*
 * End of dispose.js
 */

