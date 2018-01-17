package hub

const debugTmpl = false
const rootTmpl = `
<html>
  <head>
    <title></title>
    <style>
    body {
      font-family: HelveticaNeue-Light,Arial,sans-serif;
      font-size: 24pt;
      color: #666;
      background-image: url("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABsAAAAPCAIAAAHt9hMZAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAyJpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuMC1jMDYxIDY0LjE0MDk0OSwgMjAxMC8xMi8wNy0xMDo1NzowMSAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbnM6c3RSZWY9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZVJlZiMiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIENTNS4xIFdpbmRvd3MiIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6N0RBOEYzNTNEQkE5MTFFMTgwMkJFNjk4ODI1NkM0ODEiIHhtcE1NOkRvY3VtZW50SUQ9InhtcC5kaWQ6N0RBOEYzNTREQkE5MTFFMTgwMkJFNjk4ODI1NkM0ODEiPiA8eG1wTU06RGVyaXZlZEZyb20gc3RSZWY6aW5zdGFuY2VJRD0ieG1wLmlpZDo3REE4RjM1MURCQTkxMUUxODAyQkU2OTg4MjU2QzQ4MSIgc3RSZWY6ZG9jdW1lbnRJRD0ieG1wLmRpZDo3REE4RjM1MkRCQTkxMUUxODAyQkU2OTg4MjU2QzQ4MSIvPiA8L3JkZjpEZXNjcmlwdGlvbj4gPC9yZGY6UkRGPiA8L3g6eG1wbWV0YT4gPD94cGFja2V0IGVuZD0iciI/Ph88gYkAAAB1SURBVHjaYnjz5s1/MAAyGIEUAwwABBADRAxIIoQBAghVAQwwvX37FsJCZgAEEEI/MgOHCQzYABO6iWAAEEDYTcBuAHaHYWOQYioD0QAggLCHAbGhQr7VTMR4mQRfD5S9AAFGQqxQP0lQ2S8kuJGB2mBk+hoAwlXWrXM6SBoAAAAASUVORK5C");
    }
    #user {
      width: 350px;
      height: 400px;
      margin: 100px auto;
      border: 1px solid #eee;
      box-shadow: 2px 2px 15px rgba(0, 0, 0, 0.1);
      background-color: #fff;
      background-image: -webkit-linear-gradient(left, #fafafa, #fff 15%, #fff 85%, #fafafa);
      position: relative;
      text-align: center;
    }
    #pict {
      width: 200px;
      height: 200px;
      margin: 10px auto;
      background-size: cover;
      border-radius: 500px;
      box-shadow: inset 10px -10px 20px rgba(0, 0, 0, 0.2);
      border: 2px solid #ccc;
      background-color: #666;
    }
    #name {
      text-align: center;
      text-shadow: 2px 2px 4px #ddd;
    }
    #ctrl {
      position: absolute;
      bottom: 10px;
      left: 0;
      right: 0;
      text-align: center;
      margin: 0;
    }
    #ctrl button {
      position: relative;
      border: none;
      width: 40px;
      height: 40px;
      background-color: transparent;
      background-size: 40px 40px;
      opacity: 0.8;
      background-image: url("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAFAAAABQCAYAAACOEfKtAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAA2hpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuMy1jMDExIDY2LjE0NTY2MSwgMjAxMi8wMi8wNi0xNDo1NjoyNyAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iIHhtbG5zOnN0UmVmPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VSZWYjIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtcE1NOk9yaWdpbmFsRG9jdW1lbnRJRD0ieG1wLmRpZDowMTgwMTE3NDA3MjA2ODExODIyQTlDMzJGRDM2NjlFOCIgeG1wTU06RG9jdW1lbnRJRD0ieG1wLmRpZDo0RTQ0RDBGMkU2MEQxMUUxOThFMkZBOTQ0NTJDOUI5MSIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDo0RTQ0RDBGMUU2MEQxMUUxOThFMkZBOTQ0NTJDOUI5MSIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgQ1M2IChNYWNpbnRvc2gpIj4gPHhtcE1NOkRlcml2ZWRGcm9tIHN0UmVmOmluc3RhbmNlSUQ9InhtcC5paWQ6QTIyQjg0MEY0RDIxNjgxMTgyMkE5QzMyRkQzNjY5RTgiIHN0UmVmOmRvY3VtZW50SUQ9InhtcC5kaWQ6MDE4MDExNzQwNzIwNjgxMTgyMkE5QzMyRkQzNjY5RTgiLz4gPC9yZGY6RGVzY3Jp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");
    }
    #ctrl button:hover {
      opacity: 1;
    }
    #ctrl .l {
      pointer-events: none;
      opacity: 0;
      position: absolute;
      font-size: 16px;
      top: 46px;
      left: -24px;
      background-color: #333;
      color: #fff;
      padding: 10px;
      border-radius: 4px;
      width: 70px;
      box-shadow: -2px 2px 10px rgba(0, 0, 0, 0.2);
      -webkit-transition: opacity .2s ease-in-out;
    }
    #ctrl button:hover .l {
      opacity: 1.0;
    }
    #ctrl .l div {
      position: absolute;
      top: -6px;
      left: 38px;
      -webkit-transform: rotate(45deg);
      width: 12px;
      height: 12px;
      background-color: #333;
    }
    </style>
  </head>
  <body>
    <div id="user">
      {{with .}}
      <div id="pict" style="background-image: url('{{.Picture}}')"></div>
      <div id="name">{{.Name}}</div>
      <form id="ctrl" method="POST" action="/__auth__/logout">
        <input name="x" type="hidden">
        <button type="submit">
          <div class="l"><div></div>logout</div>
        </button>
      </form>
      {{else}}
      <div id="pict"></div>
      <div id="name">Nobody Doe</div>
      {{end}}
    </div>
  </body>
</html>
`
