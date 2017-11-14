#! /bin/bash

apt-get update
# tools
apt-get install -y vim-nox tmux htop curl emacs-nox git
apt-get install -y build-essential cmake python-dev python3-dev
# languages
apt-get install -y sbcl gcc gdb rlwrap

mkdir -p ~vagrant/.vim/{autoload,bundle}
curl -LSso ~vagrant/.vim/autoload/pathogen.vim https://tpo.pe/pathogen.vim
cd ~vagrant/.vim/bundle
git clone https://github.com/rust-lang/rust.vim.git
git clone https://github.com/scrooloose/nerdtree.git


cat >> ~vagrant/.vimrc <<EOF
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
git clone https://github.com/oblivia-simplex/emacs.d ~vagrant/.emacs.d

chown -R vagrant:vagrant ~vagrant/

cd ~vagrant
su vagrant -c "wget https://sh.rustup.rs -qO rustup.sh"
su vagrant -c "chmod 777 rustup.sh && 
               ./rustup.sh --default-toolchain nightly -y"

echo "source ~/.cargo/env" >> ~/.bashrc

git clone https://github.com/unicorn-engine/unicorn.git
cd unicorn
./make.sh
sudo make install

cd ..
su vagrant -c "wget https://beta.quicklisp.org/quicklisp.lisp"

su vagrant -c 'sbcl --load quicklisp.lisp \
  --eval \
  "(progn
     (quicklisp-quickstart:install)
     (load #P\"~/quicklisp/setup.lisp\")
     (setq ql::*do-not-prompt* t) 
     (ql:add-to-init-file))"'




