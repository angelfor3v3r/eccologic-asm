import codemirror from "codemirror";
import CodeMirror from "codemirror";
import { h, Fragment, Component, createRef } from "preact";

export default class Home extends Component
{
    constructor()
    {
        super();

        // Misc member variables.
        this.enc_url     = window.location.origin + "/api/encode";
        this.dec_url     = window.location.origin + "/api/decode";
        this.code_editor = createRef(); // Codemirror DOM reference.

        // State/values from HTML elements (and some default values).
        this.state = {
            asm_mode:       "encode",
            asm_arch:       "x86-64",
            asm_x86_synatx: "intel",
            asm_code:       "",
            result:         ""
        };
    }

    cm_on_key_tab( cm )
    {
        cm.replaceSelection( Array( cm.getOption( "indentUnit" ) + 1 ).join( " " ), "end" );
    }

    componentDidMount()
    {
        this.code_mirror = codemirror.fromTextArea( this.code_editor.current, {
            lineNumbers: true,
            theme: "material",
            indentUnit: 4,
            extraKeys: {
                Tab: this.cm_on_key_tab
            }
        } );
    }

    async encdec_post( url, data )
    {
        const resp = await fetch( url, {
            method:         "POST",
            mode:           "same-origin",
            credentials:    "same-origin",
            redirect:       "follow",
            referrerPolicy: "no-referrer",
            cache:          "no-cache",
            headers: {
                "Accept": "application/json",
                "Content-Type": "application/json"
            },
            body: JSON.stringify( data )
        } );

        const status = resp.status;
        const json   = await resp.json();
        return new Promise( ( resolve ) => { return resolve( { status, json } ); } );
    }

    encode_asm()
    {
        const data = {
            arch: this.state.asm_arch,
            code: this.state.asm_code
        };

        this.setState( { result: { type: "msg", value: "Please wait..." } } );

        this.encdec_post( this.enc_url, data )
        .then( ( { status, json } ) => {
            // Okay, was there an error status code?
            const error = ( status >= 400 && status <= 500 ) ? true : false;
            if( error )
            {
                // Check if the JSON object was filled out.
                if( json && json.error )
                {
                    // Show a user-friendly error.
                    switch( json.error.status )
                    {
                        case "InvalidCodeValue":
                        {
                            this.setState( { result: { type: "err", value: "The assembly text must not be empty." } } );
                            return;
                        }

                        case "InvalidAsmCode":
                        {
                            this.setState( { result: { type: "err", value: `Something is wrong with the input assembly:\n${json.error.message}` } } );
                            return;
                        }

                        default:
                        {
                            // Show the non-user-friendly error.
                            this.setState( { result: { type: "err", value: `Error (${json.error.status}):\n${json.error.message}` } } );
                            return;
                        }
                    }
                }

                this.setState( { result: { type: "err", value: "Something bad happened (1)." } } );
                return;
            }

            // All good :)
            this.setState( { result: { type: "enc", value: json.result } } );
        } )
        .catch( ( err ) => {
            console.log( err );
            this.setState( { result: { type: "err", value: "Something bad happened (2)." } } );
        } );
    }

    decode_asm()
    {
        // TODO
    }

    on_change = ( evt ) =>
    {
        this.setState( { [evt.target.id]: evt.target.value } );
    };

    on_submit = ( evt ) =>
    {
        // Set value from the CodeMirror editor.
        this.state.asm_code = this.code_mirror.getValue();

        // Check if encoding/decoding and handle it with the API.
        const mode = this.state.asm_mode;
        switch( mode )
        {
        case "encode":
        {
            this.encode_asm();
            break;
        }

        case "decode":
        {
            this.decode_asm();
            break;
        }

        default:
        {
            console.log( "bad mode" );
            // TODO: Show error...
        }
        }

        evt.preventDefault();
    }

    render( _, { result } )
    {
        const render_result = () =>
        {
            switch( result.type )
            {
                case "msg":
                {
                    return(
                        <span>
                            {result.value}
                        </span>
                    );
                }

                case "err":
                {
                    return(
                        <>
                            <h5 class="text-danger">Error</h5>
                            <span>
                                {result.value}
                            </span>
                        </>
                    );
                }

                case "enc":
                {
                    return(
                        <span>
                            {JSON.stringify(result.value)}
                        </span>
                    );
                }

                default:
                {
                    return(
                        <>...</>
                    );
                }
            }
        };

        return(
            <main>
                <div class="container">
                    <form onSubmit={this.on_submit}>
                        <div class="mb-3">
                            <label for="asm_code" class="form-label">Assembly</label>
                            <textarea class="form-control" type="text" id="asm_code" rows="6" ref={this.code_editor}></textarea>
                        </div>
                        <div class="row g-2 align-items-center">
                            <div class="col-auto">
                                <div class="form-floating">
                                    <select class="form-select" id="asm_mode" onChange={this.on_change}>
                                        <option value="encode" selected>Encode</option>
                                        <option value="decode">Decode</option>
                                    </select>
                                    <label for="asm_mode">Mode</label>
                                </div>
                            </div>
                            <div class="col-auto">
                                <div class="form-floating">
                                    <select class="form-select" id="asm_arch" onChange={this.on_change}>
                                        <option value="x86-64" selected>x86 (64-bit)</option>
                                        <option value="x86-32">x86 (32-bit)</option>
                                        <option value="x86-16">x86 (16-bit)</option>
                                        <option value="aarch64">AArch64 (ARM64)</option>
                                    </select>
                                    <label for="asm_arch">Architecture</label>
                                </div>
                            </div>
                            <div class="col-auto">
                                <button class="btn btn-primary" type="submit">Submit</button>
                            </div>
                        </div>
                    </form>
                </div>
                <div class="container">
                    <hr/>
                    <div class="card mb-3" id="result">
                        <span class="card-header">Result</span>
                        <div class="card-body" style="white-space: pre">
                            {render_result()}
                        </div>
                    </div>
                    <div class="dropdown">
                        <button class="btn btn-primary dropdown-toggle" type="button" id="copy_result_as" data-bs-toggle="dropdown">
                            Copy as...
                        </button>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="#">C++11</a></li>
                            <li><a class="dropdown-item" href="#">C</a></li>
                            <li><a class="dropdown-item" href="#">Python</a></li>
                        </ul>
                    </div>
                </div>
            </main>
        );
    }
}