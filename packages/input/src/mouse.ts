import {type Input} from "./types"
import {mouseButtonToLinuxEventCode} from "./codes"

interface Props {
    ws: WebSocket;
    canvas: HTMLCanvasElement;
}
export class Mouse {
    protected websocket: WebSocket;
    protected canvas: HTMLCanvasElement;
    protected connected!: boolean;

    // Store references to event listeners
    private mousemoveListener: (e: MouseEvent) => void;
    private mousedownListener: (e: MouseEvent) => void;
    private mouseupListener: (e: MouseEvent) => void;
    private mousewheelListener: (e: WheelEvent) => void;

    constructor({ws, canvas}: Props) {
        this.websocket = ws;
        this.canvas = canvas;
        this.mousemoveListener = this.createMouseListener("mousemove", (e: any) => ({
            type: "MouseMove",
            x: e.movementX,
            y: e.movementY
        }));
        this.mousedownListener = this.createMouseListener("mousedown", (e: any) => ({
            type: "MouseKeyDown",
            key: this.keyToVirtualKeyCode(e.button)
        }));
        this.mouseupListener = this.createMouseListener("mouseup", (e: any) => ({
            type: "MouseKeyUp",
            key: this.keyToVirtualKeyCode(e.button)
        }));
        this.mousewheelListener = this.createMouseListener("wheel", (e: any) => ({
            type: "MouseWheel",
            x: e.deltaX,
            y: e.deltaY
        }));

        this.run()
    }

    private run() {
        //calls all the other functions
        if (!document.pointerLockElement) {
            if (this.connected) {
                this.stop()
            }
            return;
        }

        if (document.pointerLockElement == this.canvas) {
            this.connected = true
            this.canvas.addEventListener("mousemove", this.mousemoveListener);
            this.canvas.addEventListener("mousedown", this.mousedownListener);
            this.canvas.addEventListener("mouseup", this.mouseupListener);
            this.canvas.addEventListener("wheel", this.mousewheelListener);

        } else {
            if (this.connected) {
                this.stop()
            }
        }

    }

    private stop() {
        this.canvas.removeEventListener("mousemove", this.mousemoveListener);
        this.canvas.removeEventListener("mousedown", this.mousedownListener);
        this.canvas.removeEventListener("mouseup", this.mouseupListener);
        this.canvas.removeEventListener("wheel", this.mousewheelListener);
        this.connected = false;
    }

    // Helper function to create and return mouse listeners
    private createMouseListener(type: string, dataCreator: (e: Event) => Partial<Input>): (e: Event) => void {
        return (e: Event) => {
            e.preventDefault();
            e.stopPropagation();
            const data = dataCreator(e as any); // type assertion because of the way dataCreator is used
            this.websocket.send(JSON.stringify({...data, type} as Input));
        };
    }

    public dispose() {
        document.exitPointerLock();
        this.stop();
        this.connected = false;
    }

    private keyToVirtualKeyCode(code: number) {
        return mouseButtonToLinuxEventCode[code] || undefined;
    }
}