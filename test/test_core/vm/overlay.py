from __future__ import annotations

"""qcow2 overlay 创建。

每次测试 run 都应该从同一个 template image 派生一个新的 overlay。
Guest 的所有写入都落在 overlay 上，template image 不被修改。这样测试
结束后删除 overlay，就能回到干净状态。
"""

import subprocess
from pathlib import Path


def create_overlay(template_image: str | Path, overlay_path: str | Path) -> None:
    """为单条 benchmark run 创建 qcow2 overlay。

    overlay 的 backing file 是 template image。运行中的 VM 看到的是完整
    磁盘，但实际新增写入只进入 overlay。
    """

    template = Path(template_image)
    overlay = Path(overlay_path)
    overlay.parent.mkdir(parents=True, exist_ok=True)

    subprocess.run(
        [
            "qemu-img",
            "create",
            "-f",
            "qcow2",
            "-F",
            "qcow2",
            "-b",
            str(template),
            str(overlay),
        ],
        text=True,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
