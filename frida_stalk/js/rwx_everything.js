

var mem = Process.enumerateRangesSync('---')
var base = 0;

for (var i=0; i < mem.length; i++) {
    base = Number(mem[i]['base'])

    // Ignore areas with mprotect 0
    if ( mem[i]['protection'] == "---" ) {
        continue;
    }

    console.log(mem[i]['base'])
    Memory.protect(ptr(base), mem[i]['size'], 'rwx');

    // Need to call protect in page sizes
    //for (var j=0; j < mem[i]['size']; j += Process.pageSize) {
    //    //console.log('Calling protect on: ' + String(base+j));
    //    Memory.protect(ptr(base+j), Process.pageSize, 'rwx')
    //}
}

