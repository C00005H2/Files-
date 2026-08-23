// Shader taken from: http://webglsamples.googlecode.com/hg/electricflower/electricflower.html

#ifdef GL_ES
precision mediump float;
#endif

uniform sampler2D u_texture;
varying vec2 v_texCoord;
varying vec4 v_fragmentColor;


void main() {
    vec2 blurSize1 = vec2(0.0009,0);
    vec2 blurSize2 = vec2(0.0009,0.0009);
    vec2 blurSize3 = vec2(0.0009,-0.0009);
    
    vec4 substract = vec4(0.0);
    
    
	vec4 sum = vec4(0.0);
    
//    vec2 blurSize = vec2(0.0001,0.001);
//	sum += texture2D(u_texture, v_texCoord - 4.0 * blurSize) * 0.05;
//	sum += texture2D(u_texture, v_texCoord - 3.0 * blurSize) * 0.09;
//	sum += texture2D(u_texture, v_texCoord - 2.0 * blurSize) * 0.12;
//	sum += texture2D(u_texture, v_texCoord - 1.0 * blurSize) * 0.15;
//	sum += texture2D(u_texture, v_texCoord                 ) * 0.16;
//	sum += texture2D(u_texture, v_texCoord + 1.0 * blurSize) * 0.15;
//	sum += texture2D(u_texture, v_texCoord + 2.0 * blurSize) * 0.12;
//	sum += texture2D(u_texture, v_texCoord + 3.0 * blurSize) * 0.09;
//	sum += texture2D(u_texture, v_texCoord + 4.0 * blurSize) * 0.05;

    

	sum += texture2D(u_texture, v_texCoord - 2.0 * blurSize1) * 0.05;
	sum += texture2D(u_texture, v_texCoord - 1.0 * blurSize1) * 0.07;
	sum += texture2D(u_texture, v_texCoord                 ) * 0.08;
	sum += texture2D(u_texture, v_texCoord + 1.0 * blurSize1) * 0.07;
	sum += texture2D(u_texture, v_texCoord + 2.0 * blurSize1) * 0.05;
    
    
    sum += texture2D(u_texture, v_texCoord - 2.0 * blurSize2) * 0.05;
	sum += texture2D(u_texture, v_texCoord - 1.0 * blurSize2) * 0.07;
	sum += texture2D(u_texture, v_texCoord                 ) * 0.08;
	sum += texture2D(u_texture, v_texCoord + 1.0 * blurSize2) * 0.07;
	sum += texture2D(u_texture, v_texCoord + 2.0 * blurSize2) * 0.05;



    sum += texture2D(u_texture, v_texCoord - 2.0 * blurSize3) * 0.05;
	sum += texture2D(u_texture, v_texCoord - 1.0 * blurSize3) * 0.07;
	sum += texture2D(u_texture, v_texCoord                 ) * 0.08;
	sum += texture2D(u_texture, v_texCoord + 1.0 * blurSize3) * 0.07;
	sum += texture2D(u_texture, v_texCoord + 2.0 * blurSize3) * 0.05;

	


	gl_FragColor = (sum - substract) * v_fragmentColor;
}

