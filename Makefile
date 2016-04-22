EXE = MD5 SHA1 SHA3
SRCDIR = src
INCDIR = include
REPDIR = Documents
REPORT = Memoire
TEX = $(REPDIR)/tex
DIRS = $(SRCDIR) $(REPDIR) $(TEX)

.PHONY : all build clean clean-report help report lib

all : build #report

build :
	@(cd $(SRCDIR) && $(MAKE))
	@(for exe in $(EXE); do \
		cp -f $(SRCDIR)/$$exe . ; done)

test:
	@(cd $(SRCDIR) && $(MAKE) test)

report:
	@(cd $(REPDIR) \
		&& pdflatex $(REPORT) && bibtex $(REPORT)\
		&& pdflatex $(REPORT) && pdflatex $(REPORT))
	@(cd $(REPDIR) && ./.pdf_opener.sh $(REPORT).pdf &)

clean-report:
	@(cd $(REPDIR) && rm -f $(REPORT).pdf $(REPORT).aux \
		$(REPORT).log $(REPORT).toc $(REPORT).bbl $(REPORT).blg \
		$(REPORT).dvi $(REPORT).out *~)
	@(cd $(TEX) && rm -f *.dvi *.out *.log *.aux *~ *#)

clean :
	@(cd $(SRCDIR) && $(MAKE) clean)
	@(cd $(INCDIR) && rm -rf *~)
	@(rm -f *~ $(EXE) *.gcov *.gcda *.gcno)

help :
	@(echo -e "Usage :" )
	@(echo -e "  make [all]\t\tKick off a new build and the report")
	@(echo -e "  make build\t\tBuild executables")
	@(echo -e "  make report\t\tBuild the report")
	@(echo -e "  make clean\t\tRemove all files generated for executables")
	@(echo -e "  make clean-report\tRemove all report files generated")
	@(echo -e "  make help\t\tDisplay this help")
