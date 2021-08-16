import CodeMirror                            from "codemirror";
import { h, Fragment, Component, createRef } from "preact";

// Result type.
const RT = Object.freeze({
    MSG: 1,
    ERR: 2,
    DEC: 3,
    ENC: 4
});

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
            asm_mode:               "encode",
            asm_arch:               "x86-64",
            asm_x86_synatx:         "intel",
            asm_x86_syntax_enabled: true,
            asm_code:               "",
            res:                    ""
        };
    }

    componentDidMount()
    {
        this.code_mirror = CodeMirror.fromTextArea( this.code_editor.current, {
            lineNumbers: true,
            theme: "material",
            indentUnit: 4,
            extraKeys: {
                Tab: this.cm_on_key_tab
            }
        } );
    }

    cm_on_key_tab( cm )
    {
        cm.replaceSelection( Array( cm.getOption( "indentUnit" ) + 1 ).join( " " ), "end" );
    }

    set_res( type, val )
    {
        this.setState( { res: { type: type, val: val } } );
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
                "Accept":       "application/json",
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
        const arch = this.state.asm_arch;
        let data = {
            arch: arch,
            code: this.state.asm_code
        };

        // If we're in x86 mode then we can send the syntax too.
        if( arch.startsWith( "x86" ) )
        {
            data.syntax = this.state.asm_x86_synatx;
        }

        this.set_res( RT.MSG, "Please wait..." );

        // Send encoding data.
        this.encdec_post( this.enc_url, data )
        .then( ( { status, json } ) => {
            // Okay, was there an error status code?
            const error = ( status >= 400 && status <= 500 ) ? true : false;
            if( error )
            {
                // Check if the JSON object was filled out and show an error.
                if( json && json.error )
                {
                    this.set_res( RT.ERR, `Error (${json.error.status}):\n${json.error.message}` );
                    return;
                }

                this.set_res( RT.ERR, "Server returned an error status code." );
                return;
            }

            // All good ^_^.
            this.set_res( RT.ENC, json.result );
        } )
        .catch( ( err ) => {
            this.set_res( RT.ERR, `Post request failed: ${err.message}.` );
        } );
    }

    decode_asm()
    {
        const data = {
            arch: this.state.asm_arch,
            code: this.state.asm_code
        };

        this.set_res( RT.MSG, "Please wait..." );

        // Send encoding data.
        this.encdec_post( this.dec_url, data )
        .then( ( { status, json } ) => {
            // Okay, was there an error status code?
            const error = ( status >= 400 && status <= 500 ) ? true : false;
            if( error )
            {
                // Check if the JSON object was filled out and show an error.
                if( json && json.error )
                {
                    this.set_res( RT.ERR, `Error (${json.error.status}):\n${json.error.message}` );
                    return;
                }

                this.set_res( RT.ERR, "Server returned an error status code." );
                return;
            }

            // All good ^_^.
            this.set_res( RT.DEC, json.result );
        } )
        .catch( ( err ) => {
            this.set_res( RT.ERR, `Post request failed: ${err.message}.` );
        } );
    }

    on_copy_as = ( evt ) =>
    {
        const t = this.state.res.type;
        console.log( t );

        /*
        const t = this.res.type;
        if( t == RT.DEC || t == RT.ENC )
        {
            const val = this.res.val;
            switch( evt.target.id )
            {
                case "hex":
                {

                    break;
                }

                case "str":
                {
                    break;
                }

                case "arr":
                {
                    break;
                }

                case "cpp":
                {
                    break;
                }

                case "c":
                {
                    break;
                }

                case "py":
                {
                    break;
                }

                default:
                {
                    break;
                }
            }
        }
        */

        evt.preventDefault();
    }

    on_change = ( evt ) =>
    {
        const id  = evt.target.id;
        const val = evt.target.value;
        this.setState( { [id]: val } );

        // Very special case for disabling the Architecture dropdown.
        if( id === "asm_arch" )
        {
            this.setState( { asm_x86_syntax_enabled: val.startsWith( "x86" ) ? true : false } );
        }
    }

    on_submit = ( evt ) =>
    {
        // Set the state asm code text to the text from the CodeMirror editor.
        // Bail out early if it's empty client-side (this is checked server-side anyway).
        const code = this.code_mirror.getValue().trim();
        if( !code || !code.length )
        {
            this.set_res( RT.ERR, "The assembly text must not be empty." );
        }
        // We should be good to go now.
        else
        {
            this.state.asm_code = code;

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
                this.set_res( RT.ERR, "Bad mode value." );
            }
            }
        }

        evt.preventDefault();
    }

    render( _, { res } )
    {
        const render_result = () =>
        {
            const render_disasm_line = ( details ) =>
            {
                const bytes       = details.bytes;
                const byte_amount = bytes.length;
                return(
                    <>
                        <div class="col-md-auto text-secondary">
                            {details.address}
                        </div>
                        <div class="col">
                                {bytes.map( ( val, idx ) =>
                                    {
                                        let str = val;
                                        if( byte_amount > 1 && ( idx + 1 ) < byte_amount )
                                        {
                                            str += " ";
                                        }

                                        return(
                                            <>{str}</>
                                        );
                                    }
                                )}
                        </div>
                        <div class="col">
                            {details.mnemonic + " " + details.operands}
                        </div>
                    </>
                );
            }

            const render_disasm = ( details ) =>
            {
                return details.map( ( val, idx ) =>
                {
                    return(
                        <div class="row">
                            {render_disasm_line( val )}
                        </div>
                    );
                } );
            }

            const render_bytes = ( bytes, details ) =>
            {
                if( !bytes )
                {
                    return(
                        <>
                            <h5 class="text-danger">Error</h5>
                            <span>
                                No bytes...
                            </span>
                        </>
                    );
                }

                const byte_count = bytes.length;
                return(
                    <>
                        <div class="text-info">Raw hex</div>
                        <div class="mb-3 border-bottom">
                            {bytes.map( ( val, idx ) =>
                                {
                                    let str = val;
                                    if( byte_count > 1 && ( idx + 1 ) < byte_count )
                                    {
                                        str += ", ";
                                    }

                                    return(
                                        <>{str}</>
                                    );
                                }
                            )}
                        </div>
                        <div class="text-info">Disassembly</div>
                        {render_disasm( details )}
                    </>
                );
            }

            switch( res.type )
            {
                case RT.MSG:
                {
                    return(
                        <>
                            {res.val}
                        </>
                    );
                }

                case RT.ERR:
                {
                    return(
                        <>
                            <h5 class="text-danger">Error</h5>
                            {res.val}
                        </>
                    );
                }

                case RT.DEC:
                case RT.ENC:
                {
                    return render_bytes( res.val.bytes, res.val.bytes_detail );
                }

                default:
                {
                    return(
                        <>...</>
                    );
                }
            }
        }

        return(
            <main>
                <form onSubmit={this.on_submit}>
                    <div class="my-3">
                        <label for="asm_code" class="form-label">Assembly</label>
                        <textarea class="form-control" type="text" id="asm_code" rows="6" ref={this.code_editor}></textarea>
                    </div>
                    <div class="row g-2 align-items-center">
                        <div class="col-3 d-grid">
                            <button class="btn btn-primary btn-lg" type="submit">Submit</button>
                        </div>
                        <div class="col-3">
                            <div class="form-floating">
                                <select class="form-select" id="asm_mode" onChange={this.on_change}>
                                    <option value="encode" selected>Encode</option>
                                    <option value="decode">Decode</option>
                                </select>
                                <label for="asm_mode">Mode</label>
                            </div>
                        </div>
                        <div class="col-3">
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
                        <div class="col-3">
                            <div class="form-floating">
                                <select class="form-select" id="asm_x86_synatx" onChange={this.on_change} disabled={!this.state.asm_x86_syntax_enabled}>
                                    <option value="intel" selected>Intel</option>
                                    <option value="nasm">NASM</option>
                                    <option value="att">AT&T</option>
                                </select>
                                <label for="asm_x86_synatx">Syntax (x86 only)</label>
                            </div>
                        </div>
                    </div>
                </form>
                <div class="card my-3" id="result">
                    <span class="card-header">Result</span>
                    <div class="card-body" style="white-space: pre-wrap">
                        {render_result()}
                    </div>
                </div>
                <div class="dropdown">
                    <button class="btn btn-primary dropdown-toggle" type="button" id="copy_result_as" data-bs-toggle="dropdown">
                        Copy as...
                    </button>
                    <ul class="dropdown-menu" onclick={this.on_copy_as}>
                        <li><a class="dropdown-item" href="" id="hex">Raw hex</a></li>
                        <li><a class="dropdown-item" href="" id="str">String</a></li>
                        <li><a class="dropdown-item" href="" id="arr">Array</a></li>
                        <li><a class="dropdown-item" href="" id="cpp">C++11</a></li>
                        <li><a class="dropdown-item" href="" id="c">C</a></li>
                        <li><a class="dropdown-item" href="" id="py">Python</a></li>
                    </ul>
                </div>
            </main>
        );
    }
}