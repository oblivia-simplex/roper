## Last datafile plotted: "iris_numeric.data"
#set cbtics format "%o"
set cbtics ('Setosa' 0, 'Versicolor' 1, 'Virginia' 2)
set cbtics font ", 10"
set palette rgbformulae 3, 11, 6
set palette maxcolors 3
set terminal pdfcairo size 5in,5in
set out "iris_plot.pdf"
set xlabel "Map of iris.data"
plot "~/ROPER/data/iris_numeric.data" u 1:2:5 with points pt 5 palette title "Sepal", "" u 3:4:5 with points pt 9 palette title "Petal"

#    EOF
