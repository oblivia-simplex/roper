#! /bin/bash

USER=vagrant
USERHOME=/home/$USER
hostname=roper.$(domainname)
echo "nameserver 8.8.8.8" > /etc/resolv.conf

INSTALLCMD="apt-get install -y"
REPOUPDATECMD="apt-get update && apt-get upgrade -y"

$REPOUPDATECMD
# tools
$INSTALLCMD vim-nox htop curl emacs-nox git
$INSTALLCMD build-essential cmake python-dev python3-dev
$INSTALLCMD gcc gdb rlwrap
$INSTALLCMD libfixposix0 libfixposix-dev
$INSTALLCMD libevent-dev libncurses5-dev

#usermod -a -G vboxsf vagrant
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
colorscheme badwolf
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
set -g pane-border-fg green
set -g pane-active-border-fg black
set -g status-bg green
set -g status-fg white
EOF

cat > /home/$USER/.bashrc << EOF
for rc in ~/.functions.rc ~/.colors.rc ~/.envvars ~/.aliases ~/.bash_prompt
do
    [ -f "\$rc" ] && source \$rc
done

# If not running interactively, don't do anything
case \$- in
    *i*) ;;
      *) return;;
esac

# don't put duplicate lines or lines starting with space in the history.
# See bash(1) for more options
HISTCONTROL=ignoreboth

# append to the history file, don't overwrite it
shopt -s histappend

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=10000
HISTFILESIZE=200000

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# If set, the pattern "**" used in a pathname expansion context will
# match all files and zero or more directories and subdirectories.
shopt -s globstar

# make less more friendly for non-text input files, see lesspipe(1)
#[ -x /usr/bin/lesspipe ] && eval "\$(SHELL=/bin/sh lesspipe)"

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "\${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=\$(cat /etc/debian_chroot)
fi


# enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "\$(dircolors -b ~/.dircolors)" || eval "\$(dircolors -b)"
    alias ls='ls --color=auto'
    alias dir='dir --color=auto'
    alias vdir='vdir --color=auto'

    alias grep='grep -P --color=auto'
    #alias fgrep='fgrep --color=auto'
    #alias egrep='egrep --color=auto'
fi

# enable programmable completion features (you don't need to enable
# this, if it's already enabled in /etc/bash.bashrc and /etc/profile
# sources /etc/bash.bashrc).
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi
EOF

cat > $USERHOME/.bash_prompt << EOF
function makeprompt {
    EXITSTATUS="\$?"
    JOBS="\$(jobs | wc -l | tr -d ' ')"
    TIME="\$(date +%R)"
#    NESSUS="\$(nessus_ver_running)"
    GIT="\$(git_branch)" # set prompt

    DARKGREEN="\[\033[00;32m\]"
    GREEN="\[\033[01;32m\]"
    TEAL="\[\033[00;36m\]"
    DARKGREY="\[\033[01;30m\]"
    CYAN="\[\033[01;36m\]"
    LIGHTGREY="\[\033[00;37m\]"
    RED="\[\033[00;31m\]" #?
    PINK="\[\033[01;31m\]" #?
    BLACK="\[\033[00;30m\]"
    BLUE="\[\033[01;34m\]"
    DARKBLUE="\[\033[00;34m\]"
    WHITE="\[\033[01;38m\]"
    OFF="\[\033[m\]"

    NAMECOLOR=\$DARKGREEN
    HICOLOR=\$GREEN

    PS1="\${HICOLOR}-=oO( \${NAMECOLOR}\${JOBS}\${HICOLOR} )( \$NAMECOLOR\$TIME\$HICOLOR )( \$NAMECOLOR\$GIT\$HICOLOR )(\${NAMECOLOR} \u@\h\${HICOLOR} \W\${HICOLOR} )Oo=-\${NAMECOLOR}\n"

    ## flag if error
    if (( \$EXITSTATUS == 0 )); then
        PS1="\${PS1}\${HICOLOR}\\$ \${OFF}"
    else
        PS1="\${PS1}\${RED}\\$ \${OFF}"
    fi

    PS2="\${RED}| \${OFF}"
}

PROMPT_COMMAND="history -a; history -n; makeprompt"
set -o vi
EOF

cat > $USERHOME/.functions.rc <<EOF
for rc in colors.rc; do
  [ -f \$rc ] && source ~/.\${rc}
done

function swap ()
{
  t=`mktemp`
  mv \$1 \$t && \
  mv \$2 \$1 && \
  mv \$t \$2 && \
  echo "swapped \$1 and \$2"
}

function git_branch () {
  [[ "\$PWD" = "/" ]] && echo "no branch" && return
  if [ ! -d "./.git" ]; then
    (cd .. && git_branch)
  else
    git branch 2> /dev/null | grep -Po '(?<=\* ).+' 
  fi
}

mkdir -p /tmp/trash
function rm ()
{
  [ "x\$1" = "x-rf" ] && shift
  stamp=\$(date +%F-%H-%M-%S)
  d=/tmp/trash/\${stamp}
  mkdir -p \$d
  mv \$* \$d/ && echo "Moved \$* to \$d" || echo "\${RED}Failed to move \$* to trash"
}

function getmac ()
{
  ifconfig \$1 | pcregrep -o '(?<=lladdr )([0-9a-f][0-9a-f]:){5}[0-9a-f][0-9a-f]'
}

function changemac ()
{
  IF=\$1
  MAC=\$2
  b="\${GREEN}[+]\${DARKGREEN}"

  if [ `getmac \${IF}` = \${MAC} ]; then
    echo -e "\${GREEN}MAC already set\${RESET}"
  else
    echo -e "\$b Taking down \${IF}..."
    sudo ifconfig \${IF} down
    echo -e "\$b Changing mac address to \${MAC}" 
    sudo ifconfig \${IF} lladdr \${MAC}
    echo -e "\$b Bringing \${IF} back up..."
    sudo ifconfig \${IF} up
    echo -e "\$b Acquiring dhcp lease for \${IF}..."
    sudo dhclient \${IF}
  fi

  echo "\$b Testing..."
  while : ; do
    ping -c 1 google.com && break
  done
  echo -e "\${GREEN}READY\${RESET}"
}

function disasdiff ()
{
  filter="cut -d: -f2-" 
  vimdiff <(objdump -D \$1 | \$filter ) <(objdump -D \$2 | \$filter )
}

function xxdiff ()
{
  filter="cut -d: -f2-" 
  vimdiff <(xxd -g1 \$1 | \$filter) <(xxd -g1 \$2)
}

function leet ()
{
  tr a-z A-Z | tr AELTSBGO 43175690
}

function :: ()
{
  echo Launching "\$*" in background...
  exe=\$1
  shift
  nohup \$exe "\$*" &
}
EOF

cat > $USERHOME << EOF
## ANSI escape sequences for colours, zsh format
export DARKGREEN=\$'\e[00;32m'
export GREEN=\$'\e[01;32m'
export TEAL=\$'\e[00;36m'
export DARKGREY=\$'\e[01;30m'
export CYAN=\$'\e[01;36m'
export LIGHTGREY=\$'\e[00;37m'
export RED=\$'\e[00;31m' #?
export PINK=\$'\e[01;31m' #?
export BLACK=\$'\e[00;30m'
export BLUE=\$'\e[01;34m'
export DARKBLUE=\$'\e[00;34m'
export WHITE=\$'\e[01;38m'
export RESET=\$'\e[0m'
export YELLOW=\$'\e[01;33m'
export MAGENTA=\$'\e[01;35m'
export PURPLE=\$'\e[00;35m'
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
