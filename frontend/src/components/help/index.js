import { h, Fragment, Component } from "preact";
import Markdown                   from "markdown-to-jsx";

export default class Help extends Component
{
    constructor()
    {
        super();
    }

    componentDidMount()
    {

    }

    render()
    {
        return(
            <main>
                <Markdown># Coming soon...</Markdown>
            </main>
        );
    }
}