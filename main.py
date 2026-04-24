# main.py - 程序入口
"""
StorageCleaner - 智能存储空间分析与安全清理工具
Windows 版本

运行方式：
  python main.py

依赖安装：
  pip install send2trash anthropic
"""
import sys
import os

def check_dependencies():
    """检查必要依赖"""
    missing = []
    warnings = []

    try:
        import send2trash
    except ImportError:
        warnings.append("send2trash（未安装将使用永久删除模式，无法移至回收站）")

    try:
        import anthropic
    except ImportError:
        warnings.append("anthropic（未安装将无法使用 AI 解释功能）")

    if missing:
        print("缺少必要依赖：")
        for m in missing:
            print(f"  - {m}")
        print("请运行：pip install " + " ".join(m.split("（")[0] for m in missing))
        sys.exit(1)

    if warnings:
        print("可选依赖未安装（功能受限）：")
        for w in warnings:
            print(f"  - {w}")
        print("可运行：pip install send2trash anthropic  来安装全部依赖\n")

    return True


def main():
    check_dependencies()

    # 确保日志目录存在
    from config import LOG_DIR
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    import tkinter as tk
    from ui_main import StorageCleanerApp

    root = tk.Tk()

    # 在 Windows 上启用 DPI 感知
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    app = StorageCleanerApp(root)

    # 关闭时确认
    def on_close():
        if app._scanning:
            if tk.messagebox.askyesno("确认退出", "扫描正在进行中，确定要退出吗？"):
                app.scanner.cancel()
                root.destroy()
        else:
            root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
