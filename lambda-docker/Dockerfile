# Node.js 18 is the latest image as of this writing
FROM public.ecr.aws/lambda/nodejs:18

# xetex and a few related packages are required as part of the shell script the lambda function uses to convert the json report to a PDF
RUN yum install -y texlive-xetex texlive-texconfig texlive-fontspec texlive-amsfonts texlive-cm texlive-xetex-def texlive-colortbl texlive-titlesec texlive-euenc liberation-sans-fonts liberation-narrow-fonts

# A few more texlive packages are required for the conversion script that aren't packaged with yum. Install them manually, as tlmgr is not available on this image
# Note: we can't install tlmgr without manually re-installing/building the entirety of TeX, from what I can see, so just do this very crude hack
#RUN tlmgr search --global --file tabto.sty
RUN mkdir /usr/share/texlive/texmf-dist/tex/latex/tabto/
RUN curl -L http://mirrors.ctan.org/macros/latex/contrib/tabto/tabto.sty -o /usr/share/texlive/texmf-dist/tex/latex/tabto/tabto.sty
RUN texhash

# Get dependencies for building the prowler-to-text-report executable
RUN yum install -y cmake3 gcc gcc-c++ make

# Build the prowler-to-text-report executable and get it to the right place
COPY ./prowler-json-to-pdf-converter-tool-executable-project /tmp/local-prowler-json-to-pdf-converter-tool-executable-project
RUN cmake3 -S /tmp/local-prowler-json-to-pdf-converter-tool-executable-project -B /tmp/local-prowler-json-to-pdf-converter-tool-executable-project/build 
RUN cmake3 --build /tmp/local-prowler-json-to-pdf-converter-tool-executable-project/build --parallel $(nproc)
RUN mkdir ${LAMBDA_TASK_ROOT}/build
RUN cp /tmp/local-prowler-json-to-pdf-converter-tool-executable-project/build/prowler-to-text-report ${LAMBDA_TASK_ROOT}/build/prowler-to-text-report
RUN rm -rf /tmp/local-prowler-json-to-pdf-converter-tool-executable-project

# Remove no longer needed dependencies for building the prowler-to-text-report executable
RUN yum remove -y cmake3 gcc gcc-c++ make

# The cache isn't useful anymore and it takes up space in the image - remove it
RUN yum clean all
RUN rm -rf /var/cache/yum

# Can't run the lambda function without its code
COPY ./code/index.js ${LAMBDA_TASK_ROOT}

# Script for the conversion and its dependencies
COPY ./prowler-json-to-pdf-converter-tool-executable-project/convert_stdin_to_pdf.sh ${LAMBDA_TASK_ROOT}
COPY ./prowler-json-to-pdf-converter-tool-executable-project/trackitLogo.png ${LAMBDA_TASK_ROOT}

CMD [ "index.handler" ]
