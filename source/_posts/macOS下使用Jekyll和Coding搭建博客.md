---
title: macOS下使用Jekyll和Coding搭建博客
date: 2020-05-17 14:34:31
tags: [macos, jekyll, coding]
---

仅作记录。

<!-- more -->

# Preparation

环境是 macOS Mojave，像是 command-line tools、ruby 之类的安装就不记录了。用的是 Coding 提供的静态网站服务，经过测试 jekyll 3.5 可以正常部署（版本过高在部署的时候会报错），依次安装对应的 bundle 和 jekyll：

```bash
$ gem install bundle:1.15.4
$ gem install -n /usr/local/bin/ jekyll -v "3.5"
```

# Setup Site

先在 coding 上创建一个新的仓库，并开启静态网站服务，然后克隆到本地：

```bash
$ git clone xxx.git blog && cd blog
```

接下来用 `jekyll new .` 在仓库中新建静态网站，并做相关的依赖安装，最后用 `jekyll build` 生成静态网站代码：

```bash
$ bundle exec jekyll new .
$ bundle install
$ bundle exec jekyll build
```

不看 git 的话，大概会有如下的文件。大致上和 hexo 的根目录差不了太多：

```bash
$ find .
.
./_posts
./_posts/2020-05-17-welcome-to-jekyll.markdown
./.sass-cache
./.sass-cache/81a794e6149bb69272e907db97d7f50b54a1e9e5
./.sass-cache/81a794e6149bb69272e907db97d7f50b54a1e9e5/_syntax-highlighting.scssc
./.sass-cache/81a794e6149bb69272e907db97d7f50b54a1e9e5/_base.scssc
./.sass-cache/81a794e6149bb69272e907db97d7f50b54a1e9e5/_layout.scssc
./.sass-cache/27601696a600f8c750bfb957d6267563e8022d5f
./.sass-cache/27601696a600f8c750bfb957d6267563e8022d5f/minima.scssc
./404.html
./.gitignore
./index.md
./_site
./_site/feed.xml
./_site/jekyll
./_site/jekyll/update
./_site/jekyll/update/2020
./_site/jekyll/update/2020/05
./_site/jekyll/update/2020/05/17
./_site/jekyll/update/2020/05/17/welcome-to-jekyll.html
./_site/index.html
./_site/404.html
./_site/about
./_site/about/index.html
./_site/assets
./_site/assets/main.css
./_site/assets/minima-social-icons.svg
./_config.yml
./Gemfile
./Gemfile.lock
```

可以用 `jekyll serve` 在本地对网站进行预览：

```bash
$ bundle exec jekyll serve
```

最后用 git 把代码同步到远程仓库，并在 coding 上进行部署即可：

```bash
$ git add --all .
$ git commit -m "message"
$ git push origin master
```

jekyll 默认主题比较简洁，我个人比较喜欢。但好像相比 hexo 对文章的管理要麻烦一点。

# References

https://jekyllrb.com/docs/installation/
https://www.jianshu.com/p/9f198d5779e6
