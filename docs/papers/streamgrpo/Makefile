# StreamGRPO Paper Build System

.PHONY: all clean view

all: paper.pdf

paper.pdf: paper.tex references.bib
	pdflatex paper.tex
	bibtex paper
	pdflatex paper.tex
	pdflatex paper.tex

clean:
	rm -f *.aux *.bbl *.blg *.log *.out *.pdf *.toc *.fls *.fdb_latexmk *.synctex.gz

view: paper.pdf
	open paper.pdf || xdg-open paper.pdf || evince paper.pdf

# Quick check for LaTeX syntax errors without full compilation
check:
	pdflatex -draftmode -halt-on-error paper.tex

# Count words (approximation, excludes LaTeX commands)
wordcount:
	texcount -inc -incbib paper.tex
