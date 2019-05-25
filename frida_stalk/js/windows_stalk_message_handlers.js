
var GetWindowLongPtrA = new NativeFunction(Module.getExportByName('user32.dll', 'GetWindowLongPtrA'), 'pointer', ['pointer', 'int'])
var GetWindowLongPtrW = new NativeFunction(Module.getExportByName('user32.dll', 'GetWindowLongPtrW'), 'pointer', ['pointer', 'int'])
var IsWindowUnicode = new NativeFunction(Module.getExportByName('user32.dll', 'IsWindowUnicode'), 'int', ['pointer'])

var known_window_handlers = []

//
// General HWND resolver
// 
function hwnd_resolver(hwnd) {

    // Don't both with null pointer
    if ( hwnd == 0 ) {
        return
    }

    var phwnd = ptr(hwnd);
    var phandler = 0;
    
    if ( IsWindowUnicode(phwnd) ) {
        // Need it as string for the stupid Array check to work.
        phandler = GetWindowLongPtrW(phwnd, -4).toString();
    }

    else {
        phandler = GetWindowLongPtrA(phwnd, -4).toString();
    }

    // Only return NEW discoveries
    if ( known_window_handlers.indexOf(phandler) == -1 ) {
        console.log(phandler);
        known_window_handlers = known_window_handlers.concat(phandler);
    }
}

//
// Watch DispatchMessage commands
// 

Interceptor.attach(Module.getExportByName('user32.dll', 'DispatchMessageW'), {
    onEnter: function (args) {
        var hwnd = Memory.readPointer(ptr(args[0]));
        return hwnd_resolver(hwnd);
    },

    onLeave: function (retval) {}
});

Interceptor.attach(Module.getExportByName('user32.dll', 'DispatchMessageA'), {
    onEnter: function (args) {
        var hwnd = Memory.readPointer(ptr(args[0]));
        return hwnd_resolver(hwnd);
    },

    onLeave: function (retval) {}
});

//
// Watch TranslateAccelerator commands
// 

Interceptor.attach(Module.getExportByName('user32.dll', 'TranslateAcceleratorA'), {
    onEnter: function (args) {
        return hwnd_resolver(args[0]);
    },

    onLeave: function (retval) {}
});

Interceptor.attach(Module.getExportByName('user32.dll', 'TranslateAcceleratorW'), {
    onEnter: function (args) {
        return hwnd_resolver(args[0]);
    },

    onLeave: function (retval) {}
});

// TODO: Watch IsDialogMessage, DispatchMessage, SendMessage

/*
* 
* Windows Message Handling Functions get the following list of arguments
* 
* LRESULT LRESULT DefWindowProcA(
*   HWND   hWnd,
*   UINT   Msg,
*   WPARAM wParam,
*   LPARAM lParam
* );
*/
