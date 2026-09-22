# 开发与测试

在 Linux 上、仓库根目录运行：

```bash
python3 -m unittest -v
```

测试需要 Python 3.7+ 和 `ionice`。实机测试会短暂启动工作线程；低优先级测试要求内核允许当前用户降低自身调度优先级。

相关接口：[进程与线程状态](https://www.man7.org/linux/man-pages/man5/proc_pid_stat.5.html)、[调度策略](https://www.man7.org/linux/man-pages/man7/sched.7.html)。
