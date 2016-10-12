# IRC client example

Compile with:

    npm install

Load into a running process on a virtual machine (do not run this on your host):

    frida Twitter -l _agent.js

Join #frida on irc.freenode.net and talk to it:

    <oleavr> InsideTwitter: Process.arch
    <InsideTwitter> oleavr: "x64"
    <oleavr> InsideTwitter: w00t
    <InsideTwitter> oleavr: throw new ReferenceError("w00t is not defined")
