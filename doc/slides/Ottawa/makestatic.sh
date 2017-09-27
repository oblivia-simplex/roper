#! /bin/bash

cat ottawa-slides.tex \
  | sed "s,<[+|@-]*>,,g" \
  | sed "s,\\pause,,g" \
  > ottawa-slides-static.tex && latexmk -xelatex ottawa-slides-static.tex
