
How I came to make a programming language


The last few years I've been exploring how to build game engine and 3D graphics tools from scratch. This has been a really fun process, but also sometimes frustrating due to C++ and how much it makes me pull my hair out. Header files, order dependent declarations, long compile times, weird casting rules, the list just goes on. I've looked into new alternative languages, such as the Jai and the Odin programming languages, that both were started by their creators with the same frustration of C/C++. They both mostly solve the same problems that I have, but neither left me satisfied. Jai is not released to the public with its unknown release date and no plan of open sourcing it. Odin on the other hand left me with a bad debugging experience, as the debug-information is buggy and incomplete (i.e. you can't see some values in the debugger), and the compiler is somewhat slow and occationally crashes in debug-mode. This search for nicer tools led me to the question of why aren't there that many options out there? Is it really that hard to do? I just want something simple that is enjoyable to use, fast, with quick compile times, and with a few secret ideas I have sprinkled in. "Screw it, I'll do it myself", I said.

So how DO I make a (compiled) programming language? The goal is to read text files and transform them into a magical executable file that can be ran by the computer. Let's start our way back from the end, the executable file. The executable file depends on the operating system, but is not too complicated of a format to generate yourself. However, for being able to use code made in other languages like C++, in my language, it's useful to use something called a linker. The job of a linker is to take in other magical files called object files (or static library files, they're kind of the same thing), and output the executable file. This way, we can generate object files using another programming language, and ours, and then use an existing linker to generate the executable that contains all the code.

So now our task is to generate the magical object file - what is it? An object file contains the compiled machine code that the target processor can execute. Most computers in the world use X64 processors, so an object file for this kind of processor would contain a lists of X64 instructions, such as adding two numbers together, storing a value into memory, etc, for each function. Generating all of this is starting to get complicated, especially since the object file format varies per operating system, and that there are more architectures than just X64. So are there any libraries out there that would do this job for us? There is one, which is LLVM. It's a popular library that lots of compilers use since it can output to lots of different targets and it can do transformations that optimize the code to run fast. But from what I have heard and seen, it's a complicated beast with millions of lines of code and it's also very slow to run. I want my language to be enjoyable to use, and part of that is having really fast iteration times. Plus, it's nice to not depend on the shoulders of giants and to not take an hour to build the compiler itself. What to do?

We could skip all of this and just generate source code for another programming language, like C, and use their compiler as a second step. This is easy and perfectly fine; we will even get optimizations just like that! But it will take longer to compile. And perhaps the biggest problem with this is the story of debugging. If you wanted to debug your code, you'd be debugging an unreadable mess of generated C code. If we generate the object files directly, we can generate the debug information too just like the C compiler would, and use a debugger like Visual Studio to debug the code written in our language.

The solution I came up with is to have two paths for the compiler:
	1. Generate C code for when you want to get all the nice optimizations or make a build for a platform/architecture that's not supported by option 2.
	2. Generate X64 object files directly with debug information, for quick iteration times and nice debugging

The first is easier to implement than the second, but the second is still necessary. I wanted to bundle this two-path backend into its own standalone library for anyone to use and learn from, kind of as a simple alternative to LLVM. This backend then needs to abstract the basic set of operations that can be easily generated into both C and X64. Since C is meant to be a thin abstraction over the hardware, this ended up working quite naturally.

Figuring out how to generate the X64 object files with debug info wasn't super easy. So far I've only been working on generating object files on Windows. It took quite a bit of researching, testing and looking at data in a hex editor to get things to work, but the progress has been slow and steady. I initially learned about X64 assembly by this lovely guy: https://www.youtube.com/watch?v=rxsBghsrvpI. I ended up using the `zydis` disassembler/assembler library for generating the actual instructions from code. For generating object files, I studied this nice resource https://wiki.osdev.org/COFF, among with some PDF from Microsoft from 1999. If I wanted to know something worked, I could always just invoke the microsoft C compiler and look at the generated files and compare it to a file I generated myself. Godbolt [https://godbolt.org/] has also been helpful to quickly see how something would be generated in assembly. The Microsoft debug information was particularly annoying to figure out, because it's not documented anywhere, except in parts as bits and pieces of source code released by Microsoft https://github.com/microsoft/microsoft-pdb that do not even compile.

Now that we have an easy way to generate code for the computer, it's time for the language itself! The basic idea is to read in the text files and build a tree structure out of it that holds a node for each little code unit, such as an addition operator, or a function definition. This tree form is a lot easier to deal with than a string of text:

e.g.
enum NodeKind {
	NodeKind_Declaration,
	NodeKind_Number,
	NodeKind_Function,
	NodeKind_Addition,
	...
};

struct Node {
	NodeKind kind;
	
	Node* first_child;
	Node* next;
	Node* parent;
	
	union {
		struct {
			String name;
		} Declaration;
		struct {
			float value;
		} Number;
		...
	};
};

Once we have the tree, we traverse through it and make sure that the program is correct and contains no errors, i.e. you're not calling a function that expects two parameters with only one argument. We also need to give each node that results in a value, a type (such as an integer, a float, or a boolean), and make sure that the types match too. As a last step, if everything has succeeded so far, we traverse tree again and start feeding it to the backend, which takes it from there.

That's pretty much it!

With that out of the way, let me introduce you to the FFZ programming language - the good-enough programming language that is hopefully simple enough that I will finish in less than a year! Okay, maybe that is underselling it a little bit. Simplicity is a really good thing - I want the compiler to not be daunting to those who want to look into how it works or modify/extend it. I digress, here's a snake game I wrote in the language:

// (video of snake)

Here is the full source code for the game:
https://pastebin.com/nTb7dVeC

Note that I'm cheating a little bit here and using Raylib (https://www.raylib.com/) to create the window and draw the graphics.

What are some cool things about FFZ over C and C++?
- No header files
- Out of order declarations
- The user of a module decides the namespace prefix
- built-in slice type with range checking
- Named function & struct initializer arguments
- Nice error messages
- No backstabbing the programmer with undefined behaviour
- @using on struct fields
- Intuitive and searchable declaration syntax
- implicit dereferencing (no need for ->, just use .)

There are too many things to list, but let's take as example a feature I really like, the named function & struct initializer arguments.


A big goal for FFZ is giving the programmer tools to use the programming language as a library, and to deal with the code however they like. Most programming languages nowadays have large and complicated compilers that make anything else than strictly following their rulebook with the compilation process really difficult. What if you want to write an analysis tool for your code? Or make the compiler automatically insert profiling code in every function entry and exit points? Or what if you want to parse your code into an AST, and automatically generate shader code for a graphics card API? What if you want to write a simple text editor, and want to syntax-highlight the code, or a utility that automatically renames an identifier across an entire project? Exposing this kind of functionality is not a difficult problem, yet we somehow feel so powerless with the programming languages of the modern age, and being self-reliant is really difficult.

