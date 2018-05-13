// Your code goes here!
$(function () {
    // Select size input
    // When size is submitted by the user, call makeGrid()
    const submitButton = $('input[type="submit"]'),
        canvas = $('#pixel_canvas');
    //Initialize grid
    submitButton.click(function (x) {
        x.preventDefault();
        makeGrid();
        //Grid height and width
        function makeGrid() {
            let
                col = $("#input_height").val(),
                canvasColumn,
                row = $("#input_width").val(),
                canvasRow;
            //Grid creation
            for (let r = 0; r < col; r++) {
                canvasColumn += "<tr></tr>";
            }
            for (let c = 0; c < row; c++) {
                canvasRow += "<td></td>";
            }
            //Clear grid
            canvas.children().remove();
            //Add columns and rows
            canvas.append(canvasColumn);
            canvas.children().append(canvasRow);
        }
    });
    //Event Listner
    canvas.on("click", "td", function (x) {
        x.preventDefault();
        // Select color input and erase
        let color = $("#colorPicker").val(),
            defaultColor = this.style.backgroundColor;
        if (defaultColor === "") {
            $(this).css("backgroundColor", color);
        }
        else {
            $(this).css("backgroundColor", "");
        }
    });
});
