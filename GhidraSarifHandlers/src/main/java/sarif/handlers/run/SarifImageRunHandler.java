/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sarif.handlers.run;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.activation.FileTypeMap;
import javax.activation.MimeType;
import javax.activation.MimeTypeParseException;
import javax.imageio.ImageIO;

import com.contrastsecurity.sarif.Artifact;
import com.contrastsecurity.sarif.Run;

import sarif.SarifUtils;
import sarif.handlers.SarifRunHandler;
import sarif.model.SarifDataFrame;

public class SarifImageRunHandler extends SarifRunHandler {

	@Override
	public String getKey() {
		return "image";
	}
	
	@Override
	public Map<String, BufferedImage> parse() {
		Map<String, BufferedImage> res = new HashMap<>();
		Set<Artifact> artifacts = run.getArtifacts();
		if (artifacts != null) {
			for (Artifact a : artifacts) {
				try {
					MimeType type = getArtifactMimeType(a);
					if (type.getPrimaryType().equals(getKey())) {
						try {
							BufferedImage img = ImageIO.read(SarifUtils.getArtifactContent(a));
							String description = a.getDescription() == null ?
									controller.getProgram().getDescription() : a.getDescription().getText();
							res.put(description, img);
						} catch (IOException e) {
							e.printStackTrace();
						}
					}
				} catch (MimeTypeParseException e1) {
					e1.printStackTrace();
				}
			}	
		}
		return res;
	}

	public static MimeType getArtifactMimeType(Artifact artifact) throws MimeTypeParseException {
		String type = artifact.getMimeType();
		if (type == null) {
			String filename = artifact.getLocation().getUri();
			type = FileTypeMap.getDefaultFileTypeMap().getContentType(filename);
		}
		return new MimeType(type);
	}
	
	@Override
	public void handle(SarifDataFrame df, Run run) {
		this.df = df;
		this.controller = df.getController();
		this.run = run;
		Map<String, BufferedImage> res = parse();
		if (res != null) {	
			for (Entry<String, BufferedImage> entry : res.entrySet()) {
				controller.showImage(entry.getKey(), entry.getValue());
			}
		}
	}
}
