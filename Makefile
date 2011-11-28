# Makefile

SOURCE=secure-conntrack-helpers

RST2LATEX=rst2latex
RST2HTML=rst2html

PDFLATEX=pdflatex


html:
	$(RST2HTML) $(SOURCE).rst > $(SOURCE).html

all: pdf html

pdf:
	$(RST2LATEX) $(SOURCE).rst > $(SOURCE).tex
	$(PDFLATEX) $(SOURCE).tex
	$(PDFLATEX) $(SOURCE).tex
