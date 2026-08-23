#ifdef GL_ES
precision mediump float;
#endif


uniform sampler2D u_texture;
varying vec2 v_texCoord;
varying vec4 v_fragmentColor;
void main(void)
{
    // Convert to greyscale using NTSC weightings
    vec4 col = texture2D(u_texture, v_texCoord);
    
    float r=col.r*0.7;
    float g=col.g*0.7;
    float b=col.b*0.7;
   
    gl_FragColor = vec4(r, g, b, col.a);
}