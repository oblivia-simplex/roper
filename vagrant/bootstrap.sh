#! /bin/bash

USER=vagrant
USERHOME=/home/$USER
INSTALLCMD="apt-get install -y"
REPOUPDATECMD="apt-get update && apt-get upgrade -y"

$REPOUPDATECMD
# tools
$INSTALLCMD vim-nox htop curl emacs-nox git
$INSTALLCMD build-essential cmake python-dev python3-dev
$INSTALLCMD gcc gdb rlwrap
$INSTALLCMD libfixposix0 libfixposix-dev
$INSTALLCMD libevent-dev libncurses5-dev

##############
# Vim Config #
##############
mkdir -p $USERHOME/.vim/{autoload,bundle}
curl -LSso $USERHOME/.vim/autoload/pathogen.vim https://tpo.pe/pathogen.vim
cd $USERHOME/.vim/bundle
[ -d "./rust.vim" ] || git clone https://github.com/rust-lang/rust.vim.git
[ -d "./nerdtree" ] || git clone https://github.com/scrooloose/nerdtree.git
[ -d "./badwolf"  ] || git clone https://github.com/sjl/badwolf.git

cat >> $USERHOME/.vimrc <<EOF
execute pathogen#infect()
syntax on
filetype plugin indent on
set softtabstop=2
set shiftwidth=2
set expandtab
set incsearch
set history=1000
set clipboard=unnamedplus
set number
set nocompatible
set showmode
set smartcase
set smarttab
set smartindent
set autoindent
set autoread
au CursorHold * checktime
EOF

########
# TMUX #
########
TMUXVER="2.6"
cd ~
wget -q https://github.com/tmux/tmux/releases/download/${TMUXVER}/tmux-${TMUXVER}.tar.gz 
tar xvf tmux-${TMUXVER}.tar.gz
cd tmux-${TMUXVER}
./configure
make
make install
make clean

cat > $USERHOME/.tmux.conf << EOF
unbind C-b
set-option -g prefix C-t
bind-key C-t send-prefix

set-option -g historylimit 65036

bind | split-window -h
unbind %

bind r source-file ~/.tmux.conf

# mouse on
bind m set -g mouse on \\; display 'Mouse: ON'

# mouse off
bind M set -g mouse on \\; display 'Mouse: OFF'

# aesthetics
set -g status-left-length 140
set -g status-right-length 80
set -g status-left ' #(date) | #(ip addr show dev eth1 | grep -oP "(?<=inet )[0-9./]+") | '
set -g pane-border-fg magenta
set -g pane-active-border-fg red
set -g status-bg magenta
set -g status-fg black
EOF

################
# Emacs Config #
################
if [ -d "$USERHOME/.emacs.d" ] && [ -d "$USERHOME/.emacs.d/.git" ] ; then
  cd $USERHOME/.emacs.d
  git pull
else
  [ -d "$USERHOME/.emacs.d" ] && mv $USERHOME/.emacs.d /tmp/emacs.d.bak
  git clone https://github.com/oblivia-simplex/emacs.d $USERHOME/.emacs.d
fi

#############
# Languages #
#############
# Rust (user level)
cd $USERHOME
su $USER -c "wget https://sh.rustup.rs -qO rustup.sh"
su $USER -c "chmod 777 rustup.sh && 
               ./rustup.sh --default-toolchain nightly -y"

echo "source ~/.cargo/env" >> $USERHOME/.bashrc
# SBCL (systemwide)
cd ~
SBCLVER=1.4.1
TARBALL=sbcl-${SBCLVER}-x86-64-linux-binary.tar.bz2
wget "https://sourceforge.net/projects/sbcl/files/sbcl/${SBCLVER}/${TARBALL}/download?use_mirror=svwh" -qO ~/${TARBALL}
mkdir ~/sbcl_pkg 
tar xvf ${TARBALL} -C sbcl_pkg --strip-components 1
cd sbcl_pkg
sh install.sh

#############
# Libraries #
#############
cd ~
[ -d "./unicorn" ] || git clone https://github.com/unicorn-engine/unicorn.git
cd unicorn
git pull
./make.sh 
./make.sh install

cd ~
[ -d "./capstone" ] || git clone https://github.com/aquynh/capstone.git
cd capstone
git pull
./make.sh
./make.sh install

#########################
# Quicklisp (user home) #
#########################
cd $USERHOME
su $USER -c "wget https://beta.quicklisp.org/quicklisp.lisp"

su $USER -c 'sbcl --load quicklisp.lisp --eval "(quicklisp-quickstart:install)"'
su $USER -c 'sbcl --load "./quicklisp/setup.lisp" --eval "(ql-util::without-prompting (ql:add-to-init-file))"'


# a lot of files in $USERHOME will belong to root now. fix that. 
chown -R $USER:$USER $USERHOME/
