
/*
Process.enumerateThreads({
    onMatch: function(module){
        send(module);
    },
    onComplete: function(){}
})
*/
send(Process.enumerateThreadsSync());
