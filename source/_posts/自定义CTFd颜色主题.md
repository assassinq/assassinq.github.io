---
title: 自定义CTFd颜色主题
date: 2020-05-20 10:32:37
tags: [ctf, ctfd]
---

今年校赛轮到 17 级来办了，搭建平台的时候踩的一些坑记录一下。

<!-- more -->

# Setup

以前练习平台其实搭过很多次，都是用 Ubuntu 或者直接 `docker-compose up` 起镜像。后来发现 [CTFd 在 Docker Hub 上](https://hub.docker.com/r/ctfd/ctfd)是有镜像的，直接拉下来就能装了。

```bash
$ docker pull ctfd/ctfd
$ screen docker run --name="ZJGSUCTF-2020" -p 80:8000 -it ctfd/ctfd
```

进入容器进行修改：

```bash
$ docker ps -a
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS                    NAMES
729035bc1dc7        ctfd/ctfd           "/opt/CTFd/docker-en…"   42 seconds ago      Up 38 seconds       0.0.0.0:80->8000/tcp     ZJGSUCTF-2020
$ docker exec -it quizzical_mayer /bin/sh
```

可以看到容器的启动脚本 `docker-entrypoint.sh`，其中用 `gunicorn` 作为 Web 服务器：

```bash
/opt/CTFd $ tail docker-entrypoint.sh

# Start CTFd
echo "Starting CTFd"
exec gunicorn 'CTFd:create_app()' \
    --bind '0.0.0.0:8000' \
    --workers $WORKERS \
    --worker-tmp-dir "$WORKER_TEMP_DIR" \
    --worker-class "$WORKER_CLASS" \
    --access-logfile "$ACCESS_LOG" \
    --error-logfile "$ERROR_LOG"
```

# Configuration

对颜色的设置首先可以在 Admin Panel 里选择 Theme Color：

![](/pics/自定义CTFd颜色主题/1.png)

效果如下：

![](/pics/自定义CTFd颜色主题/2.png)

改了 Theme Color 后，Challenge 里的每个 Challenge Box 的颜色还是没变，显得不太协调，可以在 themes 下修改对应的 css：

```bash
/opt/CTFd/CTFd/themes/core/static/css $ vi main.min.css
```

`.btn-dark` 是默认的 Challenge Box 的颜色：

```css
.btn-dark {
  color: #fff;
  background-color: #343a40;
  border-color: #343a40;
}
```

还有修改 Solved Challenge Box 的颜色：

```bash
/opt/CTFd/CTFd/themes/core/static/css $ vi challenge-board.min.css
```

对应的样式如下：

```css
.solved-challenge {
  background-color: #37d63e !important;
  opacity: 0.4;
  border: none;
}
```

改完后的效果如下：

![](/pics/自定义CTFd颜色主题/3.png)

# Else

国外的开源项目总是会有一些问题，这里我们也要把对应的 `flag-icons.scss` 和 `__init__.py` 部分给删除，或者像 BUUOJ 一样改为 Taiwan SAR China：

```bash
/opt/CTFd/CTFd $ grep -ir "Taiwan" *
themes/core/assets/css/includes/flag-icons.scss:  // Taiwan
utils/countries/__init__.py:    ("TW", "Taiwan"),
utils/countries/__pycache__/__init__.cpython-37.pyc:St. Martin)ZPMzSt. Pierre & Miquelon)ZVCzSt. Vincent & Grenadines)ZSDZSudan)ZSRSuriname)ZSJzSvalbard & Jan Mayen)ZSZZ	Swaziland)ZSEZSweden)ZCHZ
                                                                 Switzerland)ZSYZSyria)ZTWZTaiwan)ZTJZ
```

由于这部分是用 Python 写的，不会实时更新，这里直接重启 `gunicorn` 来刷新缓存（重启第二个，也就是这里的 8 号进程）：

```bash
/opt/CTFd $ ps aux | grep gunicorn
    1 ctfd      0:00 {gunicorn} /usr/local/bin/python /usr/local/bin/gunicorn CTFd:create_app() --bind 0.0.0.0:8000 --workers 1 --worker-tmp-dir /dev/shm --worker-class gevent --access-logfile - --error-logfile -
    8 ctfd      0:01 {gunicorn} /usr/local/bin/python /usr/local/bin/gunicorn CTFd:create_app() --bind 0.0.0.0:8000 --workers 1 --worker-tmp-dir /dev/shm --worker-class gevent --access-logfile - --error-logfile -
   38 ctfd      0:00 grep gunicorn
/opt/CTFd $ kill -HUP 8
/opt/CTFd $ ps aux | grep gunicorn
    1 ctfd      0:00 {gunicorn} /usr/local/bin/python /usr/local/bin/gunicorn CTFd:create_app() --bind 0.0.0.0:8000 --workers 1 --worker-tmp-dir /dev/shm --worker-class gevent --access-logfile - --error-logfile -
   39 ctfd      0:00 {gunicorn} /usr/local/bin/python /usr/local/bin/gunicorn CTFd:create_app() --bind 0.0.0.0:8000 --workers 1 --worker-tmp-dir /dev/shm --worker-class gevent --access-logfile - --error-logfile -
   41 ctfd      0:00 grep gunicorn
```

后来在其他师傅博客上看到了[一篇完善 CTFd 功能的文章](https://www.52hertz.tech/2020/03/15/CTFd_second_develop/)，这边记录一下，以后有机会再实现。

# References

https://www.cnblogs.com/huchong/p/9844024.html
