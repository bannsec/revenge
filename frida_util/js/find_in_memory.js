function memory_scan_match (match) {
    
    if ( match.length == 0 ) {
        return;
    }

    var address = match['address'];
    var size = match['size'];

    var d = {
        'address': address,
        'size': size
    };

    total_matches.push(d);

    // Batch send
    if ( total_matches.length >= 512 ) {
        send(total_matches);
        total_matches = [];
    }
}

function memory_scan_completed () {

    if ( total_matches.length > 0 ) {
        send(total_matches);
    };

    send('DONE');
}

// Add downselect to include module here
var search_space = SEARCH_SPACE_HERE;
var total_matches = [];
var protection = null;

var base = null;
var size = null;

setTimeout(function () {
    search_space.forEach(
        function (range) {
            base = eval(range['base']);
            size = range['size'];
            protection = Process.getRangeByAddress(base).protection;

            // Protection can actually change between enumerating at the execution of scan. Try to catch that.
            if ( protection == "rw-" || protection == "rwx" || protection == "r-x") {
                Memory.scanSync(base, size, "SCAN_PATTERN_HERE").forEach( memory_scan_match );
            };
        });

    memory_scan_completed();
});

/*
setTimeout(function () {
    search_space.enumerateRangesSync('rw').forEach(
        function (range) {
            protection = Process.getRangeByAddress(range.base).protection;

            // Protection can actually change between enumerating at the execution of scan. Try to catch that.
            if ( protection == "rw-" || protection == "rwx" ) {
                Memory.scanSync(range.base, range.size, "SCAN_PATTERN_HERE").forEach( memory_scan_match );
            };
        });

    memory_scan_completed();
});
*/
