#### markdown <--> asciidoc convert.

```sh
# # markdown <-- asciidoc(badly)
# asciidoctor test.adoc
# pandoc -f html -t markdown -o sample.md test.html

# markdown <-- asciidoc
gem install kramdown-asciidoc
kramdoc -o sample.adoc README.md

# markdown --> asciidoc
asciidoc -b docbook test.adoc
pandoc -f docbook -t markdown_strict test.xml -o sample.md
```