## 在 Rust 中使用操作系统线程看起来像这样
use std::thread; // 导入标准库中的 thread 模块

fn main() {
    println!("So we start the program here!"); // 打印程序开始的消息

    // 创建第一个线程，并启动它，使用 `thread::spawn` 函数
    let t1 = thread::spawn(move || {
        // 在这个线程中，暂停执行一段时间
        thread::sleep(std::time::Duration::from_millis(200));
        // 在暂停后打印消息
        println!("We create tasks which gets run when they're finished!");
    });

    // 创建第二个线程，并启动它，使用 `thread::spawn` 函数
    let t2 = thread::spawn(move || {
        // 在这个线程中，暂停执行一段时间
        thread::sleep(std::time::Duration::from_millis(100));
        // 在暂停后打印消息
        println!("We can even chain callbacks...");

        // 在第二个线程中创建第三个线程，并启动它，使用 `thread::spawn` 函数
        let t3 = thread::spawn(move || {
            // 在这个线程中，暂停执行一段时间
            thread::sleep(std::time::Duration::from_millis(50));
            // 在暂停后打印消息
            println!("...like this!");
        });

        // 等待第三个线程执行完成
        t3.join().unwrap();
    });

    println!("While our tasks are executing we can do other stuff here."); // 打印消息，说明在执行任务时可以进行其他操作

    // 等待第一个线程执行完成
    t1.join().unwrap();
    // 等待第二个线程执行完成
    t2.join().unwrap();
}
 
这个是运行结果
So we start the program here!
While our tasks are executing we can do other stuff here.
We can even chain callbacks...
...like this!
We create tasks which gets run when they're finished!
翻译完的结果是
当我们在这里启动程序！
在我们的任务执行时，我们可以在这里做其他事情。
我们甚至可以链接回调...
...就像这样！
我们创建的任务将在它们完成时运行！
输出按照程序的逻辑顺序进行了展示，首先是程序开始的消息，然后是在主线程中打印的一条消息，说明在执行任务时可以进行其他操作。接着是第二个任务打印的消息，然后是第三个任务打印的消息，最后是第一个任务打印的消息。这证实了程序中创建的线程是按照预期的顺序执行的。
修改一下代码
use std::thread;

fn main() {
    println!("So we start the program here!");

    // 创建第一个线程
    let t1 = thread::spawn(move || {
        thread::sleep(std::time::Duration::from_millis(200));
        println!("We create tasks which gets run when they're finished!");

        // 第一个线程执行完成后，创建并启动第二个线程
        let t2 = thread::spawn(move || {
            thread::sleep(std::time::Duration::from_millis(100));
            println!("We can even chain callbacks...");
        });

        // 等待第二个线程执行完成
        t2.join().unwrap();
    });

    println!("While our tasks are executing we can do other stuff here.");

    // 等待第一个线程执行完成
    t1.join().unwrap();

    // 创建第三个线程
    let t3 = thread::spawn(move || {
        thread::sleep(std::time::Duration::from_millis(100));
        println!("We can even chain callbacks...");

        // 在第三个线程内创建第四个线程
        let t4 = thread::spawn(move || {
            thread::sleep(std::time::Duration::from_millis(50));
            println!("...like this!");

            // 在第四个线程内创建第五个线程
            let t5 = thread::spawn(move || {
                thread::sleep(std::time::Duration::from_millis(25));
                println!("And now we have a fifth thread!");
                println!("...me too");
            });

            // 等待第五个线程执行完成
            t5.join().unwrap();
        });

        // 等待第四个线程执行完成
        t4.join().unwrap();
    });

    // 等待第三个线程执行完成
    t3.join().unwrap();
}
 
这段代码的执行流程如下：

打印 "So we start the program here!"，表示程序开始执行。
创建并启动第一个线程（t1）。在这个线程中，程序暂停 200 毫秒，然后打印 "We create tasks which gets run when they're finished!"。
打印 "While our tasks are executing we can do other stuff here."，表示在等待任务执行时可以进行其他操作。
第一个线程执行完成后，创建并启动第二个线程（t2）。在这个线程中，程序暂停 100 毫秒，然后打印 "We can even chain callbacks..."。
第二个线程执行完成后，创建并启动第三个线程（t3）。在这个线程中，程序暂停 100 毫秒，然后打印 "We can even chain callbacks..."。
第三个线程执行完成后，创建并启动第四个线程（t4）。在这个线程中，程序暂停 50 毫秒，然后打印 "...like this!"。
第四个线程执行完成后，创建并启动第五个线程（t5）。在这个线程中，程序暂停 25 毫秒，然后打印 "And now we have a fifth thread!" 和 "...me too"。
所有线程执行完成后，程序结束。
## 绿色线程给的代码不安全会报错 
为每个任务创建一个线程，设置一个堆栈，保存 CPU 状态，但是rust达到1.0之前被删除了, 依赖于这些异步运行时库来提供类似的功能。这些库利用了 Rust 的异步/非阻塞特性，通过 Future 和 async/await 语法来实现高效的非阻塞 IO 操作和并发任务。
使用绿色线程的好处是可以在一个线程上并发执行许多异步任务，而不需要创建多个系统线程，从而减少了线程间切换的开销和系统资源的占用
 
 
下面是用群友的代码
use std::ptr;

const DEFAULT_STACK_SIZE: usize = 1024 * 1024 * 2;// 线程的默认栈大小，设置为 2MB
const MAX_THREADS: usize = 4;// 最大线程数，设置为 4
static mut RUNTIME: *mut Runtime = ptr::NonNull::dangling().as_ptr();//这个静态变量被定义为不安全的（unsafe），因为在多线程环境下，对其的访问可能存在竞态条件。

#[derive(Debug)]
pub struct Runtime {
    threads: Vec<Thread>,
    current: usize,
}

#[derive(PartialEq, Eq, Debug)]
enum State {
    Available,
    Running,
    Ready,
}//这段代码定义了 Runtime 结构体和 State 枚举类型，它们是构建基于线程的运行时环境所必需的组成部分。Runtime 结构体用于管理所有线程，而 State 枚举类型用于表示线程的不同状态。

struct Thread {
    id: usize,
    stack: Vec<u8>,
    ctx: ThreadContext,
    state: State,
    task: Option<Box<dyn Fn()>>,
}//这个结构体包含了线程的各种属性和行为所需的信息，例如标识符、栈、上下文、状态和任务。通过这些信息，可以对线程进行管理和操作。

impl std::fmt::Debug for Thread {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        //write!(f, "Thread {{ id: {}, state: {:?} }}", self.id, self.state)
        f.debug_struct("Thread")
            .field("id", &self.id)
            .field("ctx", &self.ctx)
            .field("state", &self.state)
            .finish()
    }
}//这段代码实现了 Debug trait 对于 Thread 结构体的自定义打印格式。在调试时，可以使用 println!("{:?}", thread) 来打印线程对象 thread 的信息，其中 thread 是一个 Thread 结构体的实例

#[derive(Debug, Default)]// 用于为结构体自动生成 Debug 和 Default trait 的实现。Debug trait 允许我们在调试时打印结构体的内部信息，Default trait 允许我们为结构体提供默认的构造函数。
#[repr(C)]// 用于与 C 语言进行交互，确保结构体的布局与 C 语言中的结构体兼容
struct ThreadContext {
    rsp: u64,
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbx: u64,
    rbp: u64,
    thread_ptr: u64,
}//用于存储线程的上下文信息,这些字段的类型都是 u64，即 64 位无符号整数，这是因为在低级编程中，通常会使用 64 位寄存器来存储上下文信息

impl Thread {
    fn new(id: usize) -> Self {
        Thread {
            id,
            stack: vec![0_u8; DEFAULT_STACK_SIZE],
            ctx: ThreadContext::default(),
            state: State::Available,
            task: None,
        }
    }
}//整体上，这个 new 关联函数用于创建并返回一个新的 Thread 实例，并为其各个字段设置初始值。这包括：

通过传入的 id 参数设置线程的唯一标识符。
创建一个默认大小的栈。
使用默认上下文值初始化线程上下文。
设置线程状态为可用。
设置任务为 None。

impl Runtime {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let base_thread = Thread {
            id: 0,
            stack: vec![0_u8; DEFAULT_STACK_SIZE],
            ctx: ThreadContext::default(),
            state: State::Running,
            task: None,
        };//这段代码实际上创建了一个带有默认 Thread（命名为 base_thread）的新 Runtime 实例

        let mut threads = vec![base_thread];
        threads[0].ctx.thread_ptr = &threads[0] as *const Thread as u64;
        let mut available_threads: Vec<Thread> = (1..MAX_THREADS).map(Thread::new).collect();
        threads.append(&mut available_threads);

        Runtime {
            threads,
            current: 0,
        }
    }

    pub fn init(&mut self) {
        unsafe { RUNTIME = self; }
    }

    pub fn run(&mut self) -> ! {
        while self.t_yield() {}
        std::process::exit(0);
    }

    fn t_return(&mut self) {
        if self.current != 0 {
            self.threads[self.current].state = State::Available;
            self.t_yield();
        }
    }

    fn t_yield(&mut self) -> bool {
        let mut pos = self.current;

        while self.threads[pos].state != State::Ready {
            pos += 1;
            if pos == self.threads.len() {
                pos = 0;
            }
            if pos == self.current {
                return false;
            }
        }

        if self.threads[self.current].state != State::Available {
            self.threads[self.current].state = State::Ready;
        }

        self.threads[pos].state = State::Running;
        let old_pos = self.current;
        self.current = pos;

        println!("[old={old_pos} => new={pos}] thread switch");
        unsafe {
            __switch(&mut self.threads[old_pos].ctx, &self.threads[pos].ctx);
        }
        println!("[id{}] after switch", self.current);
        true
    }

    pub fn spawn<F: Fn() + 'static>(f: F) {
        unsafe {
            let available = (*RUNTIME)
                .threads
                .iter_mut()
                .find(|t| t.state == State::Available)
                .expect("no available thread.");

            let size = available.stack.len();
            // align to 16 bytes: s_ptr now becomes a base pointer to the stack
            let s_ptr = available.stack.as_mut_ptr().add(size & !0xf);
            ptr::write_unaligned(s_ptr.sub(16).cast::<u64>(), guard as usize as u64);
            ptr::write_unaligned(s_ptr.sub(32).cast::<u64>(), __call as usize as u64);
            available.ctx.rsp = s_ptr.sub(32) as u64; // set the top of thread stack

            available.task = Some(Box::new(f));
            available.ctx.thread_ptr = available as *const Thread as u64;
            available.state = State::Ready;
        }
    }
}

#[no_mangle]
fn call_entry(thread: u64) {
    let thread = unsafe { &*(thread as *const Thread) };
    if let Some(f) = &thread.task {
        f();
    }
}

std::arch::global_asm!(
    ".globl __call",
    "__call:",
    "  sub   rsp, 8", // 栈地址对齐
    "  call  call_entry",
    "  add   rsp, 16", // 这里要再加一个8，这样retq使用的就是栈中的那个guard
    "  ret",
);

fn guard() {
    let rt = unsafe { &mut *RUNTIME };
    #[cfg(debug_assertions)]
    println!( // print in color in debug build
        "\u{1b}[1;31mTHREAD {} FINISHED.\u{1b}[0m",
        rt.threads[rt.current].id
    );
    #[cfg(not(debug_assertions))]
    println!( "THREAD {} FINISHED.", rt.threads[rt.current].id );
    rt.t_return();
}

pub fn yield_thread() {
    unsafe {
        (*RUNTIME).t_yield();
    };
}

std::arch::global_asm!(
    r#"
.globl __switch
__switch:
  mov  [rdi+0x00], rsp
  mov  [rdi+0x08], r15
  mov  [rdi+0x10], r14
  mov  [rdi+0x18], r13
  mov  [rdi+0x20], r12
  mov  [rdi+0x28], rbx
  mov  [rdi+0x30], rbp

  mov  rsp, 0x00[rsi]
  mov  r15, 0x08[rsi]
  mov  r14, 0x10[rsi]
  mov  r13, 0x18[rsi]
  mov  r12, 0x20[rsi]
  mov  rbx, 0x28[rsi]
  mov  rbp, 0x30[rsi]
  mov  rdi, 0x38[rsi]
  ret
"#
);

extern "C" {
    fn __switch(old: *mut ThreadContext, new: *const ThreadContext);
    fn __call(thread: u64);
}

fn info(s: &str) {
    #[cfg(debug_assertions)]
    println!("\u{1b}[1;43;30m{s}\u{1b}[0m"); // print in color in debug build
    #[cfg(not(debug_assertions))]
    println!("{s}");
}

#[cfg(not(windows))]
fn main() {
    let mut runtime = Runtime::new();
    runtime.init();
    Runtime::spawn(|| {
        info("[id1] I haven't implemented a timer in this example.");
        yield_thread();
        info("[id1 yieled] Finally, notice how the tasks are executed concurrently.");
    });
    Runtime::spawn(|| {
        info("[id2] But we can still nest tasks...");
        Runtime::spawn(|| {
            info("[id3] ...like this!");
        })
    });
    runtime.run();
}
 
这个输出展示了线程之间的切换以及任务的执行情况：
1. 首先，线程 0 启动，并在调用 `Runtime::spawn` 后切换到线程 1。
2. 线程 1 打印了一条信息后，又在调用 `Runtime::spawn` 后切换到线程 2。
3. 线程 2 打印了一条信息后，任务完成，所以该线程结束，然后切换到线程 3。
4. 线程 3 打印了一条信息后，任务完成，所以该线程结束，然后切换回线程 0。
5. 线程 0 执行最后的打印语句，并在调用 `t_yield` 后切换到线程 1。
6. 线程 1 执行最后的打印语句，任务完成，所以该线程结束，然后切换回线程 0。
## 从回调到承诺 (promises)
Promise 的作用是管理异步操作的流程，使代码更易读和维护。

具体来说，原始的嵌套定时器调用涉及了多个回调函数，它们是在前一个定时器触发后才执行的，导致了代码的嵌套和深度增加。这种结构可能会使代码难以理解和调试，并且在复杂的情况下会导致回调地狱。

通过使用 Promise，可以将异步操作（这里是定时器）包装成一个个 Promise 对象，并使用 .then() 方法将它们链接在一起。这样做的好处是可以更清晰地表达出异步操作的顺序和依赖关系，使代码结构更加扁平化和易于理解。

另外，Promise 还提供了 .catch() 方法用于处理可能出现的异常情况，以及 .finally() 方法用于在 Promise 链执行完毕后执行清理操作，这些功能都使得 Promise 成为处理异步操作的强大工具。
## Futures
什么是Future? Future是一些将在未来完成的操作。 Rust中的异步实现基于轮询,每个异步任务分成三个阶段: 1. 轮询阶段(The Poll phase). 一个Future被轮询后,会开始执行,直到被阻塞. 我们经常把轮询一个Future这部分称之为执行器(executor) 2. 等待阶段. 事件源(通常称为reactor)注册等待一个事件发生，并确保当该事件准备好时唤醒相应的Future 3. 唤醒阶段. 事件发生,相应的Future被唤醒。 现在轮到执行器(executor),就是第一步中的那个执行器，调度Future再次被轮询，并向前走一步，直到它完成或达到一个阻塞点，不能再向前走, 如此往复,直到最终完成.

Non-leaf-futures
Non-leaf-futures指的是那些我们用async关键字创建的Future.

异步程序的大部分是Non-leaf-futures，这是一种可暂停的计算。 这是一个重要的区别，因为这些Future代表一组操作。 通常，这样的任务由await 一系列leaf-future组成.
