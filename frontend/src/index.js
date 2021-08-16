import "codemirror/lib/codemirror.js"
import "bootstrap"
import "bootswatch/dist/darkly/bootstrap.css"
import "codemirror/lib/codemirror.css"
import "codemirror/theme/material.css"
import { h, render } from "preact";
import App           from "./components/app";

render( <App/>, document.body );