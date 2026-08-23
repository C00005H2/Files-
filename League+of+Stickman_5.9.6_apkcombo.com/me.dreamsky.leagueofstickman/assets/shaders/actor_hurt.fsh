
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
    float grey = dot(col.rgb, vec3(0.299, 0.587, 0.114));
    
//    float a=-2.0;
//    float b=1.5;//
//    
//    //顶点坐标－b^2/2a   x交点坐标（0，0）（－b/a,0）
//    float x=abs(1.0-grey);
//    float y=(a*x)*x+(b*x);
//    
//    float ap=1.0;
    
    
    
    
    float agr= sin(grey*3.141) * 0.8;
    
    float dr= (1.0-grey)*agr; //abs(grey-0.5)*0.8;
    gl_FragColor =  v_fragmentColor * vec4(grey+dr, grey, grey, col.a);
}
