
all:
	./build.sh

fakebuild:
	./fakebuild.sh

deploy: all output/index.html
	./deploy.sh

output/index.html: all

clean:
	$(RM) -r output

.PHONY: all deploy clean
