
all: output/index.html

output/index.html:
	nikola build

deploy: output/index.html
	./deploy.sh

clean:
	$(RM) -r output

