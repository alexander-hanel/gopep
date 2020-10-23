# gopep
Go Lang Portable Executable Parser 


# Notes


### Go Versions 

- [go1.15](https://golang.org/dl/go1.15.src.tar.gz)
- [go1.14](https://golang.org/dl/go1.14.src.tar.gz)
- [go1.13](https://golang.org/dl/go1.13.src.tar.gz)
- [go1.12](https://golang.org/dl/go1.12.src.tar.gz)
- [go1.11](https://golang.org/dl/go1.11.src.tar.gz)
- [go1.10](https://golang.org/dl/go1.10.src.tar.gz)
- [go1.09](https://golang.org/dl/go1.9.src.tar.gz)
- [go1.08](https://golang.org/dl/go1.8.src.tar.gz)
- [go1.07](https://golang.org/dl/go1.7.src.tar.gz)
- [go1.06](https://golang.org/dl/go1.6.src.tar.gz)

### Compile Executables 

Hello World

```
package main
import "fmt"
func main() {
    fmt.Println("Hello, World!")
}
```

#### Compile 64 Bit 

`OOS=windows GOARCH=amd64 go build -o ~/hello-stripped-64.exe  helloworld.go`

#### Compile 32 Bit 
`OOS=windows GOARCH=386 go build -o ~/hello-stripped-64.exe  helloworld.go`

#### Compile 64 Bit Stripped 

`OOS=windows GOARCH=amd64 go build -o ~/hello-stripped-64.exe -ldflags="-s -w" helloworld.go`

#### Compile 32 Bit Stripped 
`OOS=windows GOARCH=386 go build -o ~/hello-stripped-64.exe -ldflags="-s -w" helloworld.go`

### Moduledata
Via [Say Hello to Moduledata Note](https://lekstu.ga/posts/hello-moduledata/)
- moduledata can be located in the `.text` or `.data` sections
- Is present in stripped binaries. As long as "-s -w" is correct for compiling stripped binaries. 
- Defined in `symtab.go`
- `pclntable` a table that holds mappings between source code line numbers and the program counter. 
 - Used for stack traces. Not removed if stripped. 
 - Includes the full file path and name of the source file at compile time and the name of the function 
- `ftab` or `functab` short for function tab. Used by the runtime function `FuncForPC`
- PTR size is stored in the binary. 
```
func moduledataverify1(datap *moduledata) {
	// See golang.org/s/go12symtab for header: 0xfffffffb,
	// two zero bytes, a byte giving the PC quantum,
	// and a byte giving the pointer width in bytes.
```
Don't need to check the bit version. 
```
.text:00520D60 runtime_pclntab dd 0FFFFFFFBh           ; DATA XREF: .data:runtime_firstmoduledata↓o
.text:00520D64         db 0
.text:00520D65         db 0
.text:00520D66         db    1
.text:00520D67         db    4
```

### .symtab
- Symbol table information about.
- Functions and global variables.
- Regardless of `-g` compile switch.
- Every relocatable object file.
- Has a symbol table in `.symtab`.
- The symbol table in `.symtab`.
- No entries for local variables.
- The symbol table inside a compiler.
- Does have entries for local variables.

#### Parsing Coff from symtab 
 - `n_name` has another check. If the first four bytes are null (00 00 00 00) then the last four byte are an offset into the string table. 
 - The start of the string table can be found by `FileHeader.PointeToSybolTable + (FileHeader.NumberOfSymbols * 18)`.
 - In ELF executables there is another section named `.strtab` that appears to be similar.

```
stucture of coff table, well kind of
{
    char		n_name[8];	/* Symbol Name */
    long		n_value;	/* Value of Symbol */
    short		n_scnum;	/* Section Number */
    unsigned short	n_type;		/* Symbol Type */
    char		n_sclass;	/* Storage Class */
    char		n_numaux;	/* Auxiliary Count */
}
```
source: https://wiki.osdev.org/COFF#String_Table

### Stripped Binaries
 - Stripped binaries for Go Windows executables can be identified by traversing the section names. 
  - If "/" is present in a section name then the binary is not stripped. 
  - If the section `.symtab` is filled with null (`\x00`) bytes the binary is stripped. 

# Resources 
* [Dissecting Go Binaries](https://www.grant.pizza/dissecting-go-binaries/)
* [Go: Overview of the Compiler](https://medium.com/a-journey-with-go/go-overview-of-the-compiler-4e5a153ca889)
* [Go compiler internals: adding a new statement to Go - Part 1](https://eli.thegreenplace.net/2019/go-compiler-internals-adding-a-new-statement-to-go-part-1/)
* [Go compiler internals: adding a new statement to Go - Part 2](https://eli.thegreenplace.net/2019/go-compiler-internals-adding-a-new-statement-to-go-part-2/)
* [Reversing GO binaries like a pro](https://rednaga.io/2016/09/21/reversing_go_binaries_like_a_pro/)
* [How a Go Program Compiles down to Machine Code](https://getstream.io/blog/how-a-go-program-compiles-down-to-machine-code/)
* [Analyzing Golang Executables](https://www.pnfsoftware.com/blog/analyzing-golang-executables/)
* [Go Reverse Engineering Tool Kit](https://go-re.tk/)
* [go-internals book](https://cmc.gitbook.io/go-internals/)
* [Reconstructing Program Semantics from Go Binaries](http://home.in.tum.de/~engelke/pubs/1709-ma.pdf)
* [The Go low-level calling convention on x86-64](https://dr-knz.net/go-calling-convention-x86-64.html)
* [Golang Internals](https://www.altoros.com/blog/golang-internals-part-1-main-concepts-and-project-structure/) (1 of 6)
* [Go Series by Joakim Kennedy](https://lekstu.ga/tags/go/)
* [Reverse Engineering Go, Part I](https://blog.osiris.cyber.nyu.edu/2019/12/19/go-deepdive/)
* [Yet Another Golang binary parser for IDAPro](https://github.com/0xjiayu/go_parser)
