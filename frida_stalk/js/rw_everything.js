
//
// Sometimes windows won't let us rwx pages, but will let us rw otherwise r pages.
// 

var mem = Process.enumerateRangesSync('r--')
var base = 0;

for (var i=0; i < mem.length; i++) {

    // Ignore areas with mprotect 0
    if ( mem[i]['protection'] != "r--" ) {
        continue;
    }

    Memory.protect(ptr(base), mem[i]['size'], 'rw-');
}

